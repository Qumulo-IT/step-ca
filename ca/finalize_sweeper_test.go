package ca

import (
	"context"
	"testing"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sweeperRun struct {
	ctx  context.Context
	db   acme.DB
	auth acme.CertificateAuthority
}

func TestCA_reloadFinalizeSweeper(t *testing.T) {
	runs := make(chan sweeperRun, 4)
	orig := runFinalizeSweeper
	t.Cleanup(func() { runFinalizeSweeper = orig })
	runFinalizeSweeper = func(ctx context.Context, db acme.DB, auth acme.CertificateAuthority) {
		runs <- sweeperRun{ctx, db, auth}
		<-ctx.Done()
	}
	next := func() sweeperRun {
		t.Helper()
		select {
		case r := <-runs:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("sweeper was not started")
			return sweeperRun{}
		}
	}
	done := func(ctx context.Context) {
		t.Helper()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("sweeper was not stopped")
		}
	}

	oldDB, oldAuth := &acme.MockDB{}, &authority.Authority{}
	ca := &CA{auth: oldAuth, acmeDB: oldDB, baseContext: context.Background()}
	ca.startFinalizeSweeper(ca.baseContext, ca.acmeDB, ca.auth)
	r1 := next()
	assert.Same(t, oldDB, r1.db)
	assert.Same(t, oldAuth, r1.auth)

	newDB, newAuth := &acme.MockDB{}, &authority.Authority{}
	ca.reloadFinalizeSweeper(&CA{auth: newAuth, acmeDB: newDB, baseContext: context.Background()})
	done(r1.ctx)
	r2 := next()
	assert.Same(t, newDB, r2.db)
	assert.Same(t, newAuth, r2.auth)
	assert.Same(t, newDB, ca.acmeDB)

	require.True(t, ca.stopFinalizeSweeper())
	done(r2.ctx)
	assert.False(t, ca.stopFinalizeSweeper())

	// A stopped sweeper is not restarted by a reload.
	ca.reloadFinalizeSweeper(&CA{auth: newAuth, acmeDB: newDB, baseContext: context.Background()})
	select {
	case <-runs:
		t.Fatal("stopped sweeper was restarted")
	case <-time.After(100 * time.Millisecond):
	}
}
