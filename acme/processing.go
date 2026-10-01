package acme

import (
	"context"
	"time"
)

// ProcessingOrder records an order whose certificate is being issued
// asynchronously, so that issuance can be resumed if the issuing process dies.
type ProcessingOrder struct {
	OrderID         string    `json:"orderID"`
	ProvisionerName string    `json:"provisionerName"`
	CSR             []byte    `json:"csr"`
	ClaimedBy       string    `json:"claimedBy"`
	ClaimedAt       time.Time `json:"claimedAt"`
}

// AsyncFinalizeDB is implemented by databases that support asynchronous order
// finalization.
type AsyncFinalizeDB interface {
	// TransitionOrderStatus atomically changes the status of an order from
	// one status to another. It returns false if the order does not have the
	// from status.
	TransitionOrderStatus(ctx context.Context, orderID string, from, to Status) (bool, error)
	// CreateProcessingOrder stores a new processing order. It fails if one
	// already exists for the same order.
	CreateProcessingOrder(ctx context.Context, po *ProcessingOrder) error
	ListProcessingOrders(ctx context.Context) ([]*ProcessingOrder, error)
	// ClaimProcessingOrder takes over a processing order if its current claim
	// is older than staleBefore. It returns false if the order is gone or was
	// claimed more recently.
	ClaimProcessingOrder(ctx context.Context, orderID, owner string, staleBefore time.Time) (*ProcessingOrder, bool, error)
	DeleteProcessingOrder(ctx context.Context, orderID string) error
}
