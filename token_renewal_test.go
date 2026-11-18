package ovirtclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ovirtclientlog "github.com/ovirt/go-ovirt-client-log/v3"
)

type reconnectToken struct {
	session int
	expiry  time.Time
}

// Guard server state so reconnect and API concurrency can be checked with the
// race detector. Session expiry is advanced explicitly without clock changes.
type reconnectEngine struct {
	mu                sync.Mutex
	server            *httptest.Server
	logins            int
	firstDue          bool
	sessionMaximum    time.Duration
	mode              string
	firstToken        string
	firstExpiry       time.Time
	oldSessionExpired bool
	tokens            map[string]reconnectToken
	loginStarted      chan struct{}
	allowLogin        chan struct{}
}

func newReconnectEngine(t *testing.T) *reconnectEngine {
	e := &reconnectEngine{tokens: make(map[string]reconnectToken)}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "password" ||
				r.Form.Get("username") != "test@internal" || r.Form.Get("password") != "test" ||
				r.Form.Get("refresh_token") != "" {
				t.Error("reconnect must perform a fresh password login")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			e.mu.Lock()
			e.logins++
			sequence := e.logins
			mode, firstDue, maximum := e.mode, e.firstDue, e.sessionMaximum
			firstExpiry, started, allow := e.firstExpiry, e.loginStarted, e.allowLogin
			e.mu.Unlock()
			if sequence == 2 && started != nil {
				close(started)
				<-allow
			}
			if sequence > 1 && mode == "login failure" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "authentication unavailable")
				return
			}
			lifetime := 10 * time.Minute
			if maximum > 0 && maximum < lifetime {
				lifetime = maximum
			}
			issuedAt := time.Now().Truncate(time.Second)
			if sequence == 1 && firstDue {
				issuedAt = issuedAt.Add(-(lifetime - lifetime/10))
			}
			expiry := issuedAt.Add(lifetime)
			if sequence > 1 && mode == "unchanged expiry" {
				expiry, issuedAt = firstExpiry, firstExpiry.Add(-lifetime)
			}
			if sequence > 1 && mode == "expired token" {
				expiry = time.Now().Add(-time.Second)
				issuedAt = expiry.Add(-lifetime)
			}
			payload := fmt.Sprintf(`{"iat":%d,"exp":%d,"session_state":"session-%d"}`, issuedAt.Unix(), expiry.Unix(), sequence)
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			if sequence > 1 && mode == "opaque token" {
				token, expiry = "opaque-test-token", time.Time{}
			}
			if sequence > 1 && mode == "empty token" {
				token = ""
			}
			e.mu.Lock()
			e.tokens[token] = reconnectToken{session: sequence, expiry: expiry}
			if sequence == 1 {
				e.firstToken, e.firstExpiry = token, expiry
			}
			e.mu.Unlock()
			fmt.Fprintf(w, `{"access_token":%q,"exp":"9223372036854775807"}`, token)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		e.mu.Lock()
		record, exists := e.tokens[token]
		reject := !exists || (record.session == 1 && e.oldSessionExpired) ||
			(record.session > 1 && e.mode == "API rejection") ||
			(!record.expiry.IsZero() && !time.Now().Before(record.expiry))
		e.mu.Unlock()
		if reject {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `<html><body>Unauthorized</body></html>`)
			return
		}
		fmt.Fprint(w, `<api/>`)
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *reconnectEngine) client(t *testing.T, verify func(Client) error) *oVirtClient {
	client, err := NewWithVerify(e.server.URL+"/ovirt-engine/api", "test@internal", "test", TLS().Insecure(), ovirtclientlog.NewNOOPLogger(), nil, verify)
	if err != nil {
		t.Fatal(err)
	}
	return client.(*oVirtClient)
}

func TestReconnectUpdatesSharedClients(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		t.Run(fmt.Sprintf("scheduled=%v", scheduled), func(t *testing.T) {
			e := newReconnectEngine(t)
			e.firstDue = scheduled
			client := e.client(t, nil)
			contextClient, sdk := client.WithContext(context.Background()), client.GetSDKClient()
			service := sdk.SystemService()
			t.Log("Authenticate through an existing context client, then use the common reconnect path")
			if err := contextClient.Test(); err != nil {
				t.Fatal(err)
			}
			if scheduled {
				if changed, err := client.ReconnectIfDue(); err != nil || !changed {
					t.Fatalf("scheduled reconnect failed: changed=%v error=%v", changed, err)
				}
			} else if err := client.Reconnect(); err != nil {
				t.Fatal(err)
			}
			e.mu.Lock()
			e.oldSessionExpired = true
			e.mu.Unlock()
			t.Log("Root, context, SDK and existing service handles use replacement authentication")
			for _, check := range []func() error{
				func() error { return client.Test() }, func() error { return contextClient.Test() }, sdk.Test,
				func() error { _, err := service.Get().Send(); return err },
			} {
				if err := check(); err != nil {
					t.Fatal(err)
				}
			}
			if client.GetSDKClient() != sdk {
				t.Fatal("reconnect replaced the SDK pointer")
			}
			if changed, err := client.ReconnectIfDue(); err != nil || changed {
				t.Fatal("replacement token was reconnected before its deadline")
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.logins != 2 {
				t.Fatalf("got %d logins, want initial login and one reconnect", e.logins)
			}
		})
	}
}

func TestReconnectFailurePreservesAuthentication(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		for _, mode := range []string{"login failure", "empty token", "API rejection", "expired token", "opaque token", "unchanged expiry"} {
			if !scheduled && (mode == "opaque token" || mode == "unchanged expiry") {
				continue // Explicit reconnect does not require an extended JWT deadline.
			}
			t.Run(fmt.Sprintf("scheduled=%v/%s", scheduled, mode), func(t *testing.T) {
				e := newReconnectEngine(t)
				e.firstDue = scheduled
				client := e.client(t, nil)
				if err := client.Test(); err != nil {
					t.Fatal(err)
				}
				previousExpiry, _ := client.conn.TokenExpiry()
				e.mu.Lock()
				e.mode = mode
				e.mu.Unlock()
				t.Log("Candidate failure preserves active authentication and its deadline")
				var err error
				if scheduled {
					var changed bool
					changed, err = client.ReconnectIfDue()
					if changed {
						t.Fatal("failed reconnect reported publication")
					}
				} else {
					err = client.Reconnect()
				}
				if err == nil {
					t.Fatal("invalid candidate was accepted")
				}
				if expiry, _ := client.conn.TokenExpiry(); !expiry.Equal(previousExpiry) {
					t.Fatal("candidate failure changed active expiry")
				}
				if err := client.Test(); err != nil {
					t.Fatalf("active authentication was lost: %v", err)
				}
				e.mu.Lock()
				e.mode = ""
				e.mu.Unlock()
				t.Log("A subsequent attempt succeeds through the same reconnect path")
				if scheduled {
					if changed, err := client.ReconnectIfDue(); err != nil || !changed {
						t.Fatalf("scheduled retry failed: changed=%v error=%v", changed, err)
					}
				} else if err := client.Reconnect(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestReconnectSerializesScheduledCalls(t *testing.T) {
	e := newReconnectEngine(t)
	e.firstDue = true
	client := e.client(t, nil)
	if err := client.Test(); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.loginStarted, e.allowLogin = make(chan struct{}), make(chan struct{})
	started, allow := e.loginStarted, e.allowLogin
	e.mu.Unlock()
	var release sync.Once
	defer release.Do(func() { close(allow) })
	forcedResult := make(chan error, 1)
	go func() { forcedResult <- client.Reconnect() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("explicit reconnect did not start candidate login")
	}
	t.Log("API calls keep using the old token while candidate login is blocked")
	apiResult := make(chan error, 1)
	go func() { apiResult <- client.Test() }()
	select {
	case err := <-apiResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("candidate login blocked readers of the active token")
	}
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for n := 0; n < 20; n++ {
		policy := ReconnectPolicy{LifetimePercentage: 50}
		if n%2 == 0 {
			policy = ReconnectPolicy{Interval: time.Minute}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			changed, err := client.ReconnectIfDue(policy)
			if err == nil && changed {
				err = errors.New("scheduled caller duplicated the explicit reconnect")
			}
			results <- err
		}()
	}
	release.Do(func() { close(allow) })
	if err := <-forcedResult; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logins != 2 {
		t.Fatalf("got %d logins; reconnect callers did not share the lock", e.logins)
	}
}

func TestReconnectSupportsOpaqueAuthentication(t *testing.T) {
	e := newReconnectEngine(t)
	client := e.client(t, nil)
	if err := client.Test(); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.mode = "opaque token"
	e.mu.Unlock()
	t.Log("Explicit reconnect retains support for valid authentication without JWT timing")
	if err := client.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if err := client.Test(); err != nil {
		t.Fatal(err)
	}
	if changed, err := client.ReconnectIfDue(); err == nil || changed {
		t.Fatal("scheduled reconnect guessed an opaque token lifetime")
	}
}

func TestReconnectVerificationAndLazyStartup(t *testing.T) {
	e := newReconnectEngine(t)
	client := e.client(t, nil)
	e.mu.Lock()
	initialLogins := e.logins
	e.mu.Unlock()
	if initialLogins != 0 {
		t.Fatal("unverified construction performed a login")
	}
	if changed, err := client.ReconnectIfDue(); err != nil || changed {
		t.Fatal("scheduled reconnect bypassed lazy initial authentication")
	}
	t.Log("Verification can reconnect the detached candidate without reentering the active mutex")
	result := make(chan error, 1)
	go func() {
		_, err := NewWithVerify(e.server.URL+"/ovirt-engine/api", "test@internal", "test", TLS().Insecure(), ovirtclientlog.NewNOOPLogger(), nil,
			func(candidate Client) error { return candidate.Reconnect() })
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("verification reentered the active reconnect mutex")
	}
}

func TestReconnectVerifierFailurePreservesAuthentication(t *testing.T) {
	e := newReconnectEngine(t)
	reject := false
	client := e.client(t, func(candidate Client) error {
		if err := candidate.Test(); err != nil {
			return err
		}
		if reject {
			return errors.New("custom verification rejected the candidate")
		}
		return nil
	})
	previousExpiry, _ := client.conn.TokenExpiry()
	reject = true
	t.Log("Custom verifier failure leaves the previous connection active")
	if err := client.Reconnect(); err == nil {
		t.Fatal("custom verification failure was ignored")
	}
	if expiry, _ := client.conn.TokenExpiry(); !expiry.Equal(previousExpiry) {
		t.Fatal("failed verification changed active expiry")
	}
	if err := client.Test(); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectStartsNewSSOSession(t *testing.T) {
	e := newReconnectEngine(t)
	e.firstDue, e.sessionMaximum = true, 2*time.Minute
	client := e.client(t, nil)
	if err := client.Test(); err != nil {
		t.Fatal(err)
	}
	t.Log("The shorter SSO session maximum triggers the shared reconnect path at 90 percent")
	if changed, err := client.ReconnectIfDue(); err != nil || !changed {
		t.Fatalf("SSO maximum was not accounted for: changed=%v error=%v", changed, err)
	}
	e.mu.Lock()
	e.oldSessionExpired = true
	oldToken := e.firstToken
	e.mu.Unlock()
	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/ovirt-engine/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+oldToken)
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("original session remained valid in the test engine")
	}
	if err := client.Test(); err != nil {
		t.Fatalf("replacement session failed after original expiry: %v", err)
	}
}

func TestMockScheduledReconnect(t *testing.T) {
	t.Log("Mock clients expose scheduled reconnect without authentication state")
	client := NewMock()
	reconnector, ok := client.(interface {
		ReconnectIfDue(...ReconnectPolicy) (bool, error)
	})
	if !ok {
		t.Fatal("mock client does not expose scheduled reconnect")
	}
	if changed, err := reconnector.ReconnectIfDue(); err != nil || changed {
		t.Fatalf("unexpected mock reconnect: changed=%v error=%v", changed, err)
	}
}

func TestReconnectConfiguredPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  ReconnectPolicy
		wantDue bool
	}{
		{"percentage due", ReconnectPolicy{LifetimePercentage: 50}, true},
		{"percentage not due", ReconnectPolicy{LifetimePercentage: 99}, false},
		{"interval due", ReconnectPolicy{Interval: time.Nanosecond}, true},
		{"interval not due", ReconnectPolicy{Interval: time.Hour}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Authenticate then exercise the configured policy through the common reconnect path")
			e := newReconnectEngine(t)
			e.firstDue = true
			client := e.client(t, nil)
			if err := client.Test(); err != nil {
				t.Fatal(err)
			}
			changed, err := client.ReconnectIfDue(tc.policy)
			if err != nil || changed != tc.wantDue {
				t.Fatalf("changed=%v error=%v", changed, err)
			}
			if err := client.Test(); err != nil {
				t.Fatal(err)
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			wantLogins := 1
			if tc.wantDue {
				wantLogins++
			}
			if e.logins != wantLogins {
				t.Fatalf("logins=%d want=%d", e.logins, wantLogins)
			}
		})
	}
}

func TestReconnectIntervalSupportsOpaqueToken(t *testing.T) {
	t.Log("Explicit interval renewal works without guessing opaque token validity")
	e := newReconnectEngine(t)
	client := e.client(t, nil)
	if err := client.Test(); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.mode = "opaque token"
	e.mu.Unlock()
	policy := ReconnectPolicy{Interval: time.Nanosecond}
	for n := 0; n < 2; n++ {
		if changed, err := client.ReconnectIfDue(policy); err != nil || !changed {
			t.Fatalf("changed=%v error=%v", changed, err)
		}
		if err := client.Test(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReconnectInvalidPolicyDoesNotLogin(t *testing.T) {
	e := newReconnectEngine(t)
	client := e.client(t, nil)
	for _, policies := range [][]ReconnectPolicy{
		{{}}, {{Interval: -time.Second}}, {{LifetimePercentage: 100}},
		{{Interval: time.Minute, LifetimePercentage: 50}},
		{{Interval: time.Minute}, {LifetimePercentage: 50}},
	} {
		t.Logf("Reject invalid policy without initiating a login: %+v", policies)
		if changed, err := client.ReconnectIfDue(policies...); err == nil || changed {
			t.Fatal("invalid policy accepted")
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logins != 0 {
		t.Fatal("invalid policy triggered authentication")
	}
}
