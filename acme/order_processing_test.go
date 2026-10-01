package acme

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrder_UpdateStatus_processing(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		o := &Order{ID: "o1", Status: StatusProcessing, ExpiresAt: clock.Now().Add(time.Hour)}
		db := &MockDB{MockUpdateOrder: func(context.Context, *Order) error {
			t.Fatal("UpdateOrder must not be called")
			return nil
		}}
		require.NoError(t, o.UpdateStatus(context.Background(), db))
		assert.Equal(t, StatusProcessing, o.Status)
	})
	t.Run("expired", func(t *testing.T) {
		o := &Order{ID: "o1", Status: StatusProcessing, ExpiresAt: clock.Now().Add(-time.Minute)}
		var saved *Order
		db := &MockDB{MockUpdateOrder: func(_ context.Context, o *Order) error {
			saved = o
			return nil
		}}
		require.NoError(t, o.UpdateStatus(context.Background(), db))
		assert.Equal(t, StatusInvalid, o.Status)
		require.NotNil(t, saved)
		assert.Equal(t, StatusInvalid, saved.Status)
	})
}

func TestOrder_Finalize_processing(t *testing.T) {
	o := &Order{ID: "o1", Status: StatusProcessing, ExpiresAt: clock.Now().Add(time.Hour)}
	err := o.Finalize(context.Background(), &MockDB{}, nil, nil, nil)
	var ae *Error
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, "urn:ietf:params:acme:error:"+ErrorOrderNotReadyType.String(), ae.Type)
}
