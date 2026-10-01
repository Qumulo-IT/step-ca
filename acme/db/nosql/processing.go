package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
)

var processingOrderTable = []byte("acme_processing_orders")

var _ acme.AsyncFinalizeDB = (*DB)(nil)

// CreateProcessingOrder stores a new processing order. It fails if one already
// exists for the same order.
func (db *DB) CreateProcessingOrder(ctx context.Context, po *acme.ProcessingOrder) error {
	return db.save(ctx, po.OrderID, po, nil, "processing order", processingOrderTable)
}

// ListProcessingOrders returns all processing orders.
func (db *DB) ListProcessingOrders(_ context.Context) ([]*acme.ProcessingOrder, error) {
	entries, err := db.db.List(processingOrderTable)
	if err != nil {
		return nil, errors.Wrap(err, "error listing processing orders")
	}
	pos := make([]*acme.ProcessingOrder, 0, len(entries))
	for _, e := range entries {
		po := new(acme.ProcessingOrder)
		if err := json.Unmarshal(e.Value, po); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling processing order %s", e.Key)
		}
		pos = append(pos, po)
	}
	return pos, nil
}

// ClaimProcessingOrder takes over a processing order if its claim is older
// than staleBefore.
func (db *DB) ClaimProcessingOrder(_ context.Context, orderID, owner string, staleBefore time.Time) (*acme.ProcessingOrder, bool, error) {
	old, err := db.db.Get(processingOrderTable, []byte(orderID))
	switch {
	case nosql.IsErrNotFound(err):
		return nil, false, nil
	case err != nil:
		return nil, false, errors.Wrapf(err, "error loading processing order %s", orderID)
	}
	po := new(acme.ProcessingOrder)
	if err := json.Unmarshal(old, po); err != nil {
		return nil, false, errors.Wrapf(err, "error unmarshaling processing order %s", orderID)
	}
	if po.ClaimedAt.After(staleBefore) {
		return nil, false, nil
	}
	po.ClaimedBy = owner
	po.ClaimedAt = clock.Now()
	nu, err := json.Marshal(po)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error marshaling processing order %s", orderID)
	}
	_, swapped, err := db.db.CmpAndSwap(processingOrderTable, []byte(orderID), old, nu)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error claiming processing order %s", orderID)
	}
	if !swapped {
		return nil, false, nil
	}
	return po, true, nil
}

// DeleteProcessingOrder removes a processing order. Deleting a missing order
// is not an error.
func (db *DB) DeleteProcessingOrder(_ context.Context, orderID string) error {
	if err := db.db.Del(processingOrderTable, []byte(orderID)); err != nil && !nosql.IsErrNotFound(err) {
		return errors.Wrapf(err, "error deleting processing order %s", orderID)
	}
	return nil
}

// TransitionOrderStatus atomically changes the status of an order from one
// status to another. It returns false if the order does not have the from
// status. The swap is retried when the order changes concurrently or the
// backend reports a conflict, as badger does for concurrent transactions.
func (db *DB) TransitionOrderStatus(_ context.Context, orderID string, from, to acme.Status) (bool, error) {
	var lastErr error
	for range 10 {
		old, err := db.db.Get(orderTable, []byte(orderID))
		switch {
		case nosql.IsErrNotFound(err):
			return false, acme.NewError(acme.ErrorMalformedType, "order %s not found", orderID)
		case err != nil:
			return false, errors.Wrapf(err, "error loading order %s", orderID)
		}
		o := new(dbOrder)
		if err := json.Unmarshal(old, o); err != nil {
			return false, errors.Wrapf(err, "error unmarshaling order %s", orderID)
		}
		if o.Status != from {
			return false, nil
		}
		o.Status = to
		nu, err := json.Marshal(o)
		if err != nil {
			return false, errors.Wrapf(err, "error marshaling order %s", orderID)
		}
		_, swapped, err := db.db.CmpAndSwap(orderTable, []byte(orderID), old, nu)
		if err != nil {
			lastErr = err
			continue
		}
		if swapped {
			return true, nil
		}
	}
	if lastErr != nil {
		return false, errors.Wrapf(lastErr, "error updating order %s", orderID)
	}
	return false, errors.Errorf("error updating order %s: too much contention", orderID)
}
