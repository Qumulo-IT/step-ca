package nosql

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/nosql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	raw, err := nosql.New("badgerv2", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	db, err := New(raw)
	require.NoError(t, err)
	return db
}

func TestProcessingOrders(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	claimed := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	po := &acme.ProcessingOrder{
		OrderID: "o1", ProvisionerName: "acme", CSR: []byte{1, 2, 3},
		ClaimedBy: "pod-a", ClaimedAt: claimed,
	}

	require.NoError(t, db.CreateProcessingOrder(ctx, po))
	require.Error(t, db.CreateProcessingOrder(ctx, po), "duplicate create must fail")

	list, err := db.ListProcessingOrders(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, po, list[0])

	_, ok, err := db.ClaimProcessingOrder(ctx, "o1", "pod-b", claimed.Add(-time.Minute))
	require.NoError(t, err)
	assert.False(t, ok, "claim newer than staleBefore must not be taken")

	got, ok, err := db.ClaimProcessingOrder(ctx, "o1", "pod-b", claimed.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "pod-b", got.ClaimedBy)
	assert.True(t, got.ClaimedAt.After(claimed))

	_, ok, err = db.ClaimProcessingOrder(ctx, "o1", "pod-c", claimed.Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, ok, "freshly reclaimed row must not be taken again")

	require.NoError(t, db.DeleteProcessingOrder(ctx, "o1"))
	require.NoError(t, db.DeleteProcessingOrder(ctx, "o1"), "delete is idempotent")
	_, ok, err = db.ClaimProcessingOrder(ctx, "o1", "pod-b", time.Now())
	require.NoError(t, err)
	assert.False(t, ok, "missing row cannot be claimed")
}

func TestClaimProcessingOrder_concurrent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	require.NoError(t, db.CreateProcessingOrder(ctx, &acme.ProcessingOrder{
		OrderID: "o1", ClaimedBy: "dead", ClaimedAt: time.Now().UTC().Add(-time.Hour),
	}))

	var wins atomic.Int32
	var wg sync.WaitGroup
	staleBefore := time.Now().UTC().Add(-time.Minute)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := db.ClaimProcessingOrder(ctx, "o1", "pod-"+string(rune('a'+i)), staleBefore); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), wins.Load())
}

func TestTransitionOrderStatus(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	o := &acme.Order{AccountID: "acc1", Status: acme.StatusReady, ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, db.CreateOrder(ctx, o))

	ok, err := db.TransitionOrderStatus(ctx, o.ID, acme.StatusReady, acme.StatusProcessing)
	require.NoError(t, err)
	assert.True(t, ok)
	got, err := db.GetOrder(ctx, o.ID)
	require.NoError(t, err)
	assert.Equal(t, acme.StatusProcessing, got.Status)

	ok, err = db.TransitionOrderStatus(ctx, o.ID, acme.StatusReady, acme.StatusProcessing)
	require.NoError(t, err)
	assert.False(t, ok, "order is no longer ready")

	_, err = db.TransitionOrderStatus(ctx, "missing", acme.StatusReady, acme.StatusProcessing)
	require.Error(t, err)
}

func TestTransitionOrderStatus_concurrent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	o := &acme.Order{AccountID: "acc1", Status: acme.StatusReady, ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, db.CreateOrder(ctx, o))

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := db.TransitionOrderStatus(ctx, o.ID, acme.StatusReady, acme.StatusProcessing)
			assert.NoError(t, err)
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), wins.Load())
}
