package acme_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallstep/certificates/acme"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/nosql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDomain = "app1.example.com"

// fakeCA signs with a self-signed issuer. If release is non-nil, signing
// blocks until it is closed.
type fakeCA struct {
	prov    provisioner.Interface
	release chan struct{}
	err     error
	calls   atomic.Int32
}

func (f *fakeCA) SignWithContext(ctx context.Context, csr *x509.CertificateRequest, _ provisioner.SignOptions, _ ...provisioner.SignOption) ([]*x509.Certificate, error) {
	f.calls.Add(1)
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return []*x509.Certificate{selfSigned(csr.PublicKey, csr.DNSNames)}, nil
}
func (f *fakeCA) AreSANsAllowed(context.Context, []string) error { return nil }
func (f *fakeCA) IsRevoked(string) (bool, error)                 { return false, nil }
func (f *fakeCA) Revoke(context.Context, *authority.RevokeOptions) error {
	return nil
}
func (f *fakeCA) LoadProvisionerByName(string) (provisioner.Interface, error) {
	return f.prov, nil
}
func (f *fakeCA) GetBackdate() *time.Duration { return nil }

func selfSigned(pub crypto.PublicKey, names []string) *x509.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	crt, _ := x509.ParseCertificate(der)
	return crt
}

func newCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	return newCSRFor(t, testDomain)
}

func newCSRFor(t *testing.T, name string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
	}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

func newProv(t *testing.T) *provisioner.ACME {
	t.Helper()
	disable := false
	p := &provisioner.ACME{Type: "ACME", Name: "acme", AsyncFinalize: true}
	require.NoError(t, p.Init(provisioner.Config{Claims: provisioner.Claims{
		MinTLSDur:                  &provisioner.Duration{Duration: 5 * time.Minute},
		MaxTLSDur:                  &provisioner.Duration{Duration: 24 * time.Hour},
		DefaultTLSDur:              &provisioner.Duration{Duration: 24 * time.Hour},
		DisableRenewal:             &disable,
		DisableSmallstepExtensions: &disable,
	}}))
	return p
}

func newDB(t *testing.T) *acmeNoSQL.DB {
	t.Helper()
	raw, err := nosql.New("badgerv2", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	db, err := acmeNoSQL.New(raw)
	require.NoError(t, err)
	return db
}

func newReadyOrder(t *testing.T, db acme.DB, prov acme.Provisioner) *acme.Order {
	t.Helper()
	now := time.Now().UTC()
	o := &acme.Order{
		AccountID:     "acc1",
		ProvisionerID: "acme/" + prov.GetName(),
		Status:        acme.StatusReady,
		ExpiresAt:     now.Add(time.Hour),
		NotBefore:     now,
		NotAfter:      now.Add(24 * time.Hour),
		Identifiers:   []acme.Identifier{{Type: acme.DNS, Value: testDomain}},
	}
	require.NoError(t, db.CreateOrder(context.Background(), o))
	return o
}

func waitStatus(t *testing.T, db acme.DB, id string, want acme.Status) *acme.Order {
	t.Helper()
	var o *acme.Order
	require.Eventually(t, func() bool {
		var err error
		o, err = db.GetOrder(context.Background(), id)
		return err == nil && o.Status == want
	}, 10*time.Second, 20*time.Millisecond)
	return o
}

func TestFinalizeAsync_success(t *testing.T) {
	ctx := context.Background()
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov, release: make(chan struct{})}
	o := newReadyOrder(t, db, prov)

	require.NoError(t, o.FinalizeAsync(ctx, db, newCSR(t), ca, prov))
	assert.Equal(t, acme.StatusProcessing, o.Status)
	waitStatus(t, db, o.ID, acme.StatusProcessing)

	// A second finalize while processing is a no-op.
	o2, err := db.GetOrder(ctx, o.ID)
	require.NoError(t, err)
	require.NoError(t, o2.FinalizeAsync(ctx, db, newCSR(t), ca, prov))

	close(ca.release)
	got := waitStatus(t, db, o.ID, acme.StatusValid)
	assert.NotEmpty(t, got.CertificateID)
	assert.Equal(t, int32(1), ca.calls.Load())
	require.Eventually(t, func() bool {
		pos, err := db.ListProcessingOrders(ctx)
		return err == nil && len(pos) == 0
	}, 5*time.Second, 20*time.Millisecond)
}

func TestFinalizeAsync_failure(t *testing.T) {
	ctx := context.Background()
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov, err: errors.New("upstream said no")}
	o := newReadyOrder(t, db, prov)

	require.NoError(t, o.FinalizeAsync(ctx, db, newCSR(t), ca, prov))
	got := waitStatus(t, db, o.ID, acme.StatusInvalid)
	require.NotNil(t, got.Error)
	require.Eventually(t, func() bool {
		pos, err := db.ListProcessingOrders(ctx)
		return err == nil && len(pos) == 0
	}, 5*time.Second, 20*time.Millisecond)
}

// plainDB hides the AsyncFinalizeDB methods.
type plainDB struct{ acme.DB }

func TestFinalizeAsync_fallsBackToSync(t *testing.T) {
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)

	require.NoError(t, o.FinalizeAsync(context.Background(), plainDB{db}, newCSR(t), ca, prov))
	assert.Equal(t, acme.StatusValid, o.Status)
}

func TestIsAsyncFinalizeEnabled(t *testing.T) {
	assert.True(t, acme.IsAsyncFinalizeEnabled(newProv(t)))
	assert.False(t, acme.IsAsyncFinalizeEnabled(&provisioner.ACME{}))
	assert.False(t, acme.IsAsyncFinalizeEnabled(&acme.MockProvisioner{}))
}

func TestFinalizeAsync_concurrent(t *testing.T) {
	testFinalizeAsyncConcurrent(t, newDB(t))
}

// TestFinalizeAsync_concurrentPostgres runs the concurrency test against a
// real PostgreSQL server, whose CmpAndSwap only locks existing rows. Set
// STEPCA_TEST_POSTGRES_DSN to run it.
func TestFinalizeAsync_concurrentPostgres(t *testing.T) {
	dsn := os.Getenv("STEPCA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("STEPCA_TEST_POSTGRES_DSN is not set")
	}
	for i := range 5 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			name := fmt.Sprintf("stepca_test_%d_%d", time.Now().UnixNano(), i)
			raw, err := nosql.New("postgresql", dsn, nosql.WithDatabase(name))
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Close() })
			db, err := acmeNoSQL.New(raw)
			require.NoError(t, err)
			testFinalizeAsyncConcurrent(t, db)
		})
	}
}

func testFinalizeAsyncConcurrent(t *testing.T, db *acmeNoSQL.DB) {
	ctx := context.Background()
	prov := newProv(t)
	ca := &fakeCA{prov: prov, release: make(chan struct{})}
	o := newReadyOrder(t, db, prov)

	const n = 16
	orders := make([]*acme.Order, n)
	for i := range orders {
		oi, err := db.GetOrder(ctx, o.ID)
		require.NoError(t, err)
		orders[i] = oi
	}
	csrs := make([]*x509.CertificateRequest, n)
	for i := range csrs {
		csrs[i] = newCSR(t)
	}

	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = orders[i].FinalizeAsync(ctx, db, csrs[i], ca, prov)
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, acme.StatusProcessing, orders[i].Status)
	}

	// Exactly one request recorded its CSR while issuance is blocked.
	pos, err := db.ListProcessingOrders(ctx)
	require.NoError(t, err)
	require.Len(t, pos, 1)
	won := 0
	for _, csr := range csrs {
		if bytes.Equal(csr.Raw, pos[0].CSR) {
			won++
		}
	}
	assert.Equal(t, 1, won)

	close(ca.release)
	waitStatus(t, db, o.ID, acme.StatusValid)
	assert.Equal(t, int32(1), ca.calls.Load())
	require.Eventually(t, func() bool {
		pos, err := db.ListProcessingOrders(ctx)
		return err == nil && len(pos) == 0
	}, 5*time.Second, 20*time.Millisecond)
}

func TestFinalizeAsync_badCSR(t *testing.T) {
	ctx := context.Background()
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)

	err := o.FinalizeAsync(ctx, db, newCSRFor(t, "other.example.com"), ca, prov)
	var ae *acme.Error
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, "urn:ietf:params:acme:error:badCSR", ae.Type)

	got, err := db.GetOrder(ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusReady, got.Status)
	pos, err := db.ListProcessingOrders(ctx)
	require.NoError(t, err)
	assert.Empty(t, pos)
	assert.Equal(t, int32(0), ca.calls.Load())

	// The client can retry with a correct CSR.
	require.NoError(t, got.FinalizeAsync(ctx, db, newCSR(t), ca, prov))
	waitStatus(t, db, o.ID, acme.StatusValid)
}

// failingCreateDB fails to record processing orders.
type failingCreateDB struct{ *acmeNoSQL.DB }

func (failingCreateDB) CreateProcessingOrder(context.Context, *acme.ProcessingOrder) error {
	return errors.New("disk full")
}

func TestFinalizeAsync_createProcessingOrderFails(t *testing.T) {
	ctx := context.Background()
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)

	require.Error(t, o.FinalizeAsync(ctx, failingCreateDB{db}, newCSR(t), ca, prov))
	assert.Equal(t, acme.StatusReady, o.Status)
	got, err := db.GetOrder(ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusReady, got.Status, "order must be given back")
	assert.Equal(t, int32(0), ca.calls.Load())

	require.NoError(t, got.FinalizeAsync(ctx, db, newCSR(t), ca, prov))
	waitStatus(t, db, o.ID, acme.StatusValid)
}

func TestFinalizeAsync_existingRowForReadyOrder(t *testing.T) {
	ctx := context.Background()
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)
	// A row left behind for an order that is still ready.
	require.NoError(t, db.CreateProcessingOrder(ctx, &acme.ProcessingOrder{
		OrderID: o.ID, ProvisionerName: prov.GetName(), CSR: newCSR(t).Raw,
		ClaimedBy: "dead-pod", ClaimedAt: time.Now().UTC().Add(-acme.FinalizeTimeout - 2*time.Minute),
	}))

	require.Error(t, o.FinalizeAsync(ctx, db, newCSR(t), ca, prov))
	got, err := db.GetOrder(ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusReady, got.Status)

	// The sweeper removes the row without issuing.
	acme.SweepProcessingOrders(ctx, db, ca)
	require.Eventually(t, func() bool {
		pos, err := db.ListProcessingOrders(ctx)
		return err == nil && len(pos) == 0
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, int32(0), ca.calls.Load())

	require.NoError(t, got.FinalizeAsync(ctx, db, newCSR(t), ca, prov))
	waitStatus(t, db, o.ID, acme.StatusValid)
}

// markProcessing puts an order in the processing state with a claim of the
// given age, as if the issuing process died.
func markProcessing(t *testing.T, db *acmeNoSQL.DB, o *acme.Order, prov acme.Provisioner, csr *x509.CertificateRequest, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, db.CreateProcessingOrder(ctx, &acme.ProcessingOrder{
		OrderID: o.ID, ProvisionerName: prov.GetName(), CSR: csr.Raw,
		ClaimedBy: "dead-pod", ClaimedAt: time.Now().UTC().Add(-age),
	}))
	o.Status = acme.StatusProcessing
	require.NoError(t, db.UpdateOrder(ctx, o))
}

func TestSweepProcessingOrders_resumesStale(t *testing.T) {
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)
	markProcessing(t, db, o, prov, newCSR(t), acme.FinalizeTimeout+2*time.Minute)

	acme.SweepProcessingOrders(context.Background(), db, ca)

	waitStatus(t, db, o.ID, acme.StatusValid)
	assert.Equal(t, int32(1), ca.calls.Load())
}

func TestSweepProcessingOrders_skipsFresh(t *testing.T) {
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)
	markProcessing(t, db, o, prov, newCSR(t), time.Minute)

	acme.SweepProcessingOrders(context.Background(), db, ca)

	time.Sleep(200 * time.Millisecond)
	got, err := db.GetOrder(context.Background(), o.ID)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusProcessing, got.Status)
	assert.Equal(t, int32(0), ca.calls.Load())
}

func TestSweepProcessingOrders_deletesFinishedRow(t *testing.T) {
	ctx := context.Background()
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov}
	o := newReadyOrder(t, db, prov)
	markProcessing(t, db, o, prov, newCSR(t), acme.FinalizeTimeout+2*time.Minute)
	// The issuing process finished but died before deleting the row.
	o.Status = acme.StatusValid
	require.NoError(t, db.UpdateOrder(ctx, o))

	acme.SweepProcessingOrders(ctx, db, ca)

	require.Eventually(t, func() bool {
		pos, err := db.ListProcessingOrders(ctx)
		return err == nil && len(pos) == 0
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, int32(0), ca.calls.Load())
}

func TestSweepProcessingOrders_survivesCancel(t *testing.T) {
	db, prov := newDB(t), newProv(t)
	ca := &fakeCA{prov: prov, release: make(chan struct{})}
	o := newReadyOrder(t, db, prov)
	markProcessing(t, db, o, prov, newCSR(t), acme.FinalizeTimeout+2*time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	acme.SweepProcessingOrders(ctx, db, ca)
	require.Eventually(t, func() bool { return ca.calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	// Stopping the sweeper must not abort resumed issuance.
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(ca.release)

	waitStatus(t, db, o.ID, acme.StatusValid)
}
