package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

var (
	// FinalizeTimeout bounds asynchronous certificate issuance for one order.
	FinalizeTimeout = 10 * time.Minute
	// FinalizeSweepInterval is how often processing orders are checked for
	// abandoned issuance.
	FinalizeSweepInterval = 30 * time.Second
)

// AsyncFinalizer is implemented by provisioners that can opt in to
// asynchronous order finalization.
type AsyncFinalizer interface {
	IsAsyncFinalizeEnabled() bool
}

// IsAsyncFinalizeEnabled reports whether p opted in to asynchronous
// finalization.
func IsAsyncFinalizeEnabled(p Provisioner) bool {
	af, ok := p.(AsyncFinalizer)
	return ok && af.IsAsyncFinalizeEnabled()
}

func finalizeOwner() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// FinalizeAsync checks that the order is ready, validates the CSR, marks the
// order processing and issues the certificate in the background, as allowed by
// RFC 8555 section 7.4. If db does not implement AsyncFinalizeDB it behaves
// like Finalize.
//
// The ready to processing transition of the order is the mutual exclusion
// point: only the request that makes it records the processing order and
// starts issuance. Concurrent requests get the order as processing.
func (o *Order) FinalizeAsync(ctx context.Context, db DB, csr *x509.CertificateRequest, auth CertificateAuthority, p Provisioner) error {
	adb, ok := db.(AsyncFinalizeDB)
	if !ok {
		return o.Finalize(ctx, db, csr, auth, p)
	}
	if err := o.UpdateStatus(ctx, db); err != nil {
		return err
	}
	if ready, err := o.checkAsyncFinalizeStatus(); !ready {
		return err
	}

	// Reject CSRs the client can fix while the order is still ready.
	if _, err := o.prepareIssue(ctx, db, csr, p); err != nil {
		return err
	}

	won, err := adb.TransitionOrderStatus(ctx, o.ID, StatusReady, StatusProcessing)
	if err != nil {
		return WrapErrorISE(err, "error updating order %s", o.ID)
	}
	if !won {
		// Another request changed the order first.
		stored, err := db.GetOrder(ctx, o.ID)
		if err != nil {
			return WrapErrorISE(err, "error loading order %s", o.ID)
		}
		*o = *stored
		if err := o.UpdateStatus(ctx, db); err != nil {
			return err
		}
		_, err = o.checkAsyncFinalizeStatus()
		return err
	}
	o.Status = StatusProcessing

	if err := adb.CreateProcessingOrder(ctx, &ProcessingOrder{
		OrderID:         o.ID,
		ProvisionerName: p.GetName(),
		CSR:             csr.Raw,
		ClaimedBy:       finalizeOwner(),
		ClaimedAt:       clock.Now(),
	}); err != nil {
		// Give the order back so the client can retry. If this fails too the
		// order stays processing until it expires and becomes invalid.
		if _, rerr := adb.TransitionOrderStatus(context.WithoutCancel(ctx), o.ID, StatusProcessing, StatusReady); rerr != nil {
			log.Printf("async finalize: error reverting order %s to ready: %v", o.ID, rerr)
		} else {
			o.Status = StatusReady
		}
		return WrapErrorISE(err, "error recording processing order %s", o.ID)
	}

	log.Printf("async finalize: order %s is processing", o.ID)
	go issueAsync(context.WithoutCancel(ctx), db, adb, o.ID, csr, auth, p)
	return nil
}

// checkAsyncFinalizeStatus reports whether the order is ready to be
// finalized. If it is not, the returned error is the response to the finalize
// request, nil meaning the order is returned as is.
func (o *Order) checkAsyncFinalizeStatus() (bool, error) {
	switch o.Status {
	case StatusInvalid:
		return false, NewError(ErrorOrderNotReadyType, "order %s has been abandoned", o.ID)
	case StatusValid, StatusProcessing:
		return false, nil
	case StatusPending:
		return false, NewError(ErrorOrderNotReadyType, "order %s is not ready", o.ID)
	case StatusReady:
		return true, nil
	default:
		return false, NewErrorISE("unexpected status %s for order %s", o.Status, o.ID)
	}
}

// issueAsync issues the certificate for a processing order and records the
// outcome. The processing row is removed once the order is no longer
// processing.
func issueAsync(ctx context.Context, db DB, adb AsyncFinalizeDB, orderID string, csr *x509.CertificateRequest, auth CertificateAuthority, p Provisioner) {
	ctx, cancel := context.WithTimeout(ctx, FinalizeTimeout)
	defer cancel()

	o, err := db.GetOrder(ctx, orderID)
	if err != nil {
		log.Printf("async finalize: error loading order %s: %v", orderID, err)
		return
	}
	if err := o.UpdateStatus(ctx, db); err != nil {
		log.Printf("async finalize: error updating order %s status: %v", orderID, err)
		return
	}
	if o.Status == StatusProcessing {
		if err := o.issue(ctx, db, csr, auth, p); err != nil {
			log.Printf("async finalize: order %s failed: %v", orderID, err)
			o.Status = StatusInvalid
			o.Error = asACMEError(err)
			if err := db.UpdateOrder(context.WithoutCancel(ctx), o); err != nil {
				log.Printf("async finalize: error marking order %s invalid: %v", orderID, err)
				return
			}
		} else {
			log.Printf("async finalize: order %s is valid", orderID)
		}
	}
	if err := adb.DeleteProcessingOrder(context.WithoutCancel(ctx), orderID); err != nil {
		log.Printf("async finalize: error deleting processing order %s: %v", orderID, err)
	}
}

func asACMEError(err error) *Error {
	var ae *Error
	if errors.As(err, &ae) {
		return ae
	}
	return WrapErrorISE(err, "error finalizing order")
}

// SweepProcessingOrders resumes issuance of processing orders whose claim is
// older than FinalizeTimeout plus a grace minute, meaning the process that
// started issuance is gone. Resumed issuances run in the background.
func SweepProcessingOrders(ctx context.Context, db DB, auth CertificateAuthority) {
	adb, ok := db.(AsyncFinalizeDB)
	if !ok {
		return
	}
	pos, err := adb.ListProcessingOrders(ctx)
	if err != nil {
		log.Printf("async finalize: error listing processing orders: %v", err)
		return
	}
	staleBefore := clock.Now().Add(-(FinalizeTimeout + time.Minute))
	owner := finalizeOwner()
	for _, po := range pos {
		if !po.ClaimedAt.Before(staleBefore) {
			continue
		}
		claimed, ok, err := adb.ClaimProcessingOrder(ctx, po.OrderID, owner, staleBefore)
		if err != nil {
			log.Printf("async finalize: error claiming order %s: %v", po.OrderID, err)
			continue
		}
		if !ok {
			continue
		}
		csr, err := x509.ParseCertificateRequest(claimed.CSR)
		if err != nil {
			log.Printf("async finalize: order %s has an unreadable CSR: %v", po.OrderID, err)
			continue
		}
		p, err := loadACMEProvisioner(auth, claimed.ProvisionerName)
		if err != nil {
			log.Printf("async finalize: order %s: %v", po.OrderID, err)
			continue
		}
		log.Printf("async finalize: resuming order %s previously claimed by %s", po.OrderID, po.ClaimedBy)
		// Issuance outlives the sweeper; if the process dies the row is left
		// for another sweeper.
		go issueAsync(context.WithoutCancel(NewProvisionerContext(ctx, p)), db, adb, po.OrderID, csr, auth, p)
	}
}

func loadACMEProvisioner(auth CertificateAuthority, name string) (Provisioner, error) {
	p, err := auth.LoadProvisionerByName(name)
	if err != nil {
		return nil, fmt.Errorf("error loading provisioner %q: %w", name, err)
	}
	ap, ok := p.(Provisioner)
	if !ok {
		return nil, fmt.Errorf("provisioner %q is not an ACME provisioner", name)
	}
	return ap, nil
}

// RunFinalizeSweeper calls SweepProcessingOrders every FinalizeSweepInterval
// until ctx is done.
func RunFinalizeSweeper(ctx context.Context, db DB, auth CertificateAuthority) {
	SweepProcessingOrders(ctx, db, auth)
	t := time.NewTicker(FinalizeSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			SweepProcessingOrders(ctx, db, auth)
		}
	}
}
