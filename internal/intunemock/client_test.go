package intunemock

import (
	"context"
	"errors"
	"testing"

	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
)

// scopeTokens hands out the mock's token format, so the real client's scope
// requests are checked by the mock exactly as Entra would check them.
type scopeTokens struct{}

func (scopeTokens) Token(_ context.Context, scope string) (string, error) {
	return "mock." + scope, nil
}

// TestRealClientAgainstMock proves the mock speaks the bridge's wire format.
func TestRealClientAgainstMock(t *testing.T) {
	srv, m := newTestMock(t, Options{})
	c := intune.New(scopeTokens{}, "test", intune.Endpoints{
		GraphURL:    srv.URL + "/",
		ResourceURL: "https://api.manage.microsoft.com/",
		AppID:       intuneAppID,
	})
	ctx := context.Background()
	if err := c.Validate(ctx, "txn-ok", csrWithChallenge(t, "ok-1")); err != nil {
		t.Fatalf("ok challenge: %v", err)
	}
	if err := c.Validate(ctx, "txn-rej", csrWithChallenge(t, "reject-1")); !errors.Is(err, intune.ErrRejected) {
		t.Fatalf("reject challenge: err = %v, want ErrRejected", err)
	}
	if err := c.Validate(ctx, "txn-err", csrWithChallenge(t, "error-1")); err == nil || errors.Is(err, intune.ErrRejected) {
		t.Fatalf("error challenge: err = %v, want a non-rejection error", err)
	}
	recs := m.Records()
	if len(recs) != 3 || recs[0].Kind != "validate" || recs[0].Challenge != "ok-1" || recs[0].TransactionID != "txn-ok" {
		t.Fatalf("records = %+v", recs)
	}
}
