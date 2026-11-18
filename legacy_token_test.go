package ovirtclient

import (
	"context"
	"fmt"
	ovirtclientlog "github.com/ovirt/go-ovirt-client-log/v3"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestLegacyInvalidGrantProbeRecovery(t *testing.T) {
	for _, mode := range []string{"success", "scheduled", "login failure", "candidate rejected"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			logins := 0
			expired := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
					logins++
					if expired && mode == "login failure" {
						fmt.Fprint(w, `{"error":"access_denied"}`)
						return
					}
					expiry := time.Now().Add(7 * 24 * time.Hour)
					if mode == "scheduled" && logins == 1 {
						expiry = time.Now().Add(-time.Second)
					}
					fmt.Fprintf(w, `{"access_token":"opaque-session-%d","exp":"%d"}`, logins, expiry.UnixNano()/int64(time.Millisecond))
					return
				}
				if expired && (r.Header.Get("Authorization") == "Bearer opaque-session-1" || mode == "candidate rejected") {
					w.WriteHeader(http.StatusUnauthorized)
					fmt.Fprint(w, `<html><head><title>Error</title></head><body>invalid_grant: The provided authorization grant for the auth code has expired.</body></html>`)
					return
				}
				fmt.Fprint(w, `<api/>`)
			}))
			defer server.Close()
			client, err := NewWithVerify(server.URL+"/ovirt-engine/api", "test@internal", "test", TLS().Insecure(), ovirtclientlog.NewNOOPLogger(), nil,
				func(candidate Client) error { return candidate.WithContext(context.Background()).Test() })
			if err != nil {
				t.Fatal(err)
			}
			contextClient := client.WithContext(context.Background())
			sdk := client.(ClientWithLegacySupport).GetSDKClient()
			previousExpiry, _ := sdk.TokenExpiry()
			t.Log("Expire the SSO session before its advertised deadline; recover through the existing reconnect path")
			mu.Lock()
			expired = true
			mu.Unlock()
			if mode == "scheduled" {
				changed, reconnectErr := client.(*oVirtClient).ReconnectIfDue()
				if reconnectErr != nil || !changed {
					t.Fatalf("legacy percentage reconnect failed: changed=%v error=%v", changed, reconnectErr)
				}
			} else if mode == "success" {
				err = client.Test()
			} else {
				err = client.Test(MaxTries(2), ReconnectStrategy(client))
			}
			if mode == "success" || mode == "scheduled" {
				if err != nil {
					t.Fatal(err)
				}
				if err := contextClient.Test(MaxTries(1)); err != nil {
					t.Fatal(err)
				}
				if sdk != client.(ClientWithLegacySupport).GetSDKClient() {
					t.Fatal("recovery replaced shared SDK")
				}
			} else if err == nil {
				t.Fatal("failed recovery reported success")
			} else if expiry, _ := sdk.TokenExpiry(); !expiry.Equal(previousExpiry) {
				t.Fatal("failed recovery changed active expiry")
			}
			mu.Lock()
			defer mu.Unlock()
			wantLogins := 2
			if mode == "login failure" || mode == "candidate rejected" {
				wantLogins = 3 // Initial login plus two bounded recovery attempts.
			}
			if logins != wantLogins {
				t.Fatalf("expected %d bounded logins, got %d", wantLogins, logins)
			}
		})
	}
}

// This opt-in check only authenticates and reads the API root; it creates no disks.
func TestLegacyTokenLiveEngine(t *testing.T) {
	if os.Getenv("OVIRT_TOKEN_RENEWAL_LIVE") != "1" {
		t.Skip("set OVIRT_TOKEN_RENEWAL_LIVE=1 and OVIRT_URL, OVIRT_USERNAME, OVIRT_PASSWORD, OVIRT_CAFILE for an authenticated live check")
	}
	t.Log("Authenticate against the configured engine with certificate verification")
	client, err := NewWithVerify(os.Getenv("OVIRT_URL"), os.Getenv("OVIRT_USERNAME"), os.Getenv("OVIRT_PASSWORD"),
		TLS().CACertsFromFile(os.Getenv("OVIRT_CAFILE")), ovirtclientlog.NewNOOPLogger(), NewExtraSettings().WithProxy(""), nil)
	if err != nil {
		t.Fatal("could not construct live client")
	}
	if err := client.Test(); err != nil {
		t.Fatal("initial API authorization failed")
	}
	sdk := client.(ClientWithLegacySupport).GetSDKClient()
	if expiry, err := sdk.TokenExpiry(); err != nil || !expiry.After(time.Now()) {
		t.Fatal("engine did not supply a usable expiry")
	}
	t.Log("Force an acquisition-interval renewal without changing engine timeout configuration")
	changed, err := client.(*oVirtClient).ReconnectIfDue(ReconnectPolicy{Interval: time.Nanosecond})
	if err != nil || !changed {
		t.Fatal("live scheduled reconnect failed")
	}
	if sdk != client.(ClientWithLegacySupport).GetSDKClient() {
		t.Fatal("live reconnect replaced SDK")
	}
	if err := sdk.Test(); err != nil {
		t.Fatal("replacement API authorization failed")
	}
	t.Log("Live engine expiry metadata and replacement authentication verified")
}
