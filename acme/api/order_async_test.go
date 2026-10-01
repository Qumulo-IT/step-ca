package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/pemutil"
)

// asyncMockDB adds AsyncFinalizeDB methods to acme.MockDB.
type asyncMockDB struct {
	*acme.MockDB
	mu          sync.Mutex
	created     []*acme.ProcessingOrder
	transitions int
}

func (m *asyncMockDB) TransitionOrderStatus(_ context.Context, _ string, from, to acme.Status) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if from == acme.StatusReady && to == acme.StatusProcessing {
		m.transitions++
	}
	return true, nil
}

func (m *asyncMockDB) CreateProcessingOrder(_ context.Context, po *acme.ProcessingOrder) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created = append(m.created, po)
	return nil
}
func (m *asyncMockDB) ListProcessingOrders(context.Context) ([]*acme.ProcessingOrder, error) {
	return nil, nil
}
func (m *asyncMockDB) ClaimProcessingOrder(context.Context, string, string, time.Time) (*acme.ProcessingOrder, bool, error) {
	return nil, false, nil
}
func (m *asyncMockDB) DeleteProcessingOrder(context.Context, string) error { return nil }

func TestHandler_FinalizeOrder_async(t *testing.T) {
	mockMustAuthority(t, &mockCA{})
	p := &provisioner.ACME{Type: "ACME", Name: "async", AsyncFinalize: true}
	require.NoError(t, p.Init(provisioner.Config{Claims: globalProvisionerClaims}))

	_csr, err := pemutil.Read("../../authority/testdata/certs/foo.csr")
	require.NoError(t, err)
	csr := _csr.(*x509.CertificateRequest)
	payload, err := json.Marshal(&FinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csr.Raw)})
	require.NoError(t, err)

	now := clock.Now()
	db := &asyncMockDB{MockDB: &acme.MockDB{
		MockGetOrder: func(context.Context, string) (*acme.Order, error) {
			return &acme.Order{
				ID: "orderID", AccountID: "accountID",
				ProvisionerID: fmt.Sprintf("acme/%s", p.GetName()),
				Status:        acme.StatusReady, ExpiresAt: now.Add(time.Hour),
				Identifiers: []acme.Identifier{{Type: "dns", Value: "example.acme.com"}},
			}, nil
		},
		MockUpdateOrder: func(context.Context, *acme.Order) error { return nil },
	}}

	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("ordID", "orderID")
	ctx := acme.NewProvisionerContext(context.Background(), p)
	ctx = context.WithValue(ctx, accContextKey, &acme.Account{ID: "accountID"})
	ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{value: payload})
	ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
	ctx = newBaseContext(ctx, db, acme.NewLinker("test.ca.smallstep.com", "acme"))

	req := httptest.NewRequest(http.MethodPost, "https://test.ca.smallstep.com/acme/async/order/orderID/finalize", http.NoBody).WithContext(ctx)
	w := httptest.NewRecorder()
	FinalizeOrder(w, req)
	res := w.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "5", res.Header.Get("Retry-After"))
	var got acme.Order
	require.NoError(t, json.NewDecoder(res.Body).Decode(&got))
	assert.Equal(t, acme.StatusProcessing, got.Status)
	db.mu.Lock()
	defer db.mu.Unlock()
	assert.Equal(t, 1, db.transitions)
	require.Len(t, db.created, 1)
	assert.Equal(t, "orderID", db.created[0].OrderID)
}
