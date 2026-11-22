package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sylvinus/agent-vm/internal/managedproxy"
	"go.yaml.in/yaml/v3"
)

func TestProxyRelayRouteAPIValidationRefreshAndDelete(t *testing.T) {
	s := testServer(t)
	p, _ := managedproxy.Load(s.profile)
	exitID := p.Selected
	if err := p.Import("relays", "https://example.com/sub?token=secret-sub-token", []byte(`proxies:
  - {name: relay-a, type: http, server: 192.0.2.10, port: 1080, password: secret-relay-password}
  - {name: relay-b, type: http, server: 192.0.2.11, port: 1081, password: secret-relay-password-2}
`), "relays", 0, ""); err != nil {
		t.Fatal(err)
	}
	if err := p.Save(s.profile); err != nil {
		t.Fatal(err)
	}

	oldValidate, oldStart, oldFetch := validateProxyCore, startProxyCore, fetchProxySource
	t.Cleanup(func() { validateProxyCore, startProxyCore, fetchProxySource = oldValidate, oldStart, oldFetch })
	validateProxyCore = func(_ context.Context, profile string, p managedproxy.Store) error {
		_, err := p.Runtime(profile)
		return err
	}
	failStart := false
	startProxyCore = func(context.Context, string, managedproxy.Store) error {
		if failStart {
			return errors.New("simulated start error")
		}
		return nil
	}

	// Reject mixed node_ids + hops.
	if err := s.changeProxy("route", proxyInput{
		NodeIDs: []string{exitID},
		Hops: []managedproxy.RouteHop{
			{Relay: &managedproxy.RelayGroup{Strategy: managedproxy.RelayStrategyFallback, SourceID: "relays"}},
			{NodeID: exitID},
		},
	}, nil); err == nil {
		t.Fatal("mixed node_ids and hops accepted")
	}

	// Reject relay as final exit.
	if err := s.changeProxy("route", proxyInput{
		Hops: []managedproxy.RouteHop{
			{NodeID: exitID},
			{Relay: &managedproxy.RelayGroup{Strategy: managedproxy.RelayStrategyFallback, SourceID: "relays"}},
		},
	}, nil); err == nil {
		t.Fatal("relay accepted as final exit")
	}

	// Apply auto-switch fallback relay via HTTP POST /api/proxy/route.
	reqBody, _ := json.Marshal(proxyInput{
		Hops: []managedproxy.RouteHop{
			{Relay: &managedproxy.RelayGroup{Strategy: managedproxy.RelayStrategyFallback, SourceID: "relays"}},
			{NodeID: exitID},
		},
	})
	if w := request(s, "POST", "/api/proxy/route", s.origin, string(reqBody), true); w.Code != http.StatusOK {
		t.Fatalf("POST /api/proxy/route failed: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		job := s.jobs.snapshot()
		s.mu.Unlock()
		if !job.Running {
			if job.Error != "" {
				t.Fatal(job.Error)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay route job timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}

	applied, _ := managedproxy.Load(s.profile)
	if len(applied.RouteHops) != 2 || applied.RouteHops[0].Relay == nil || applied.RouteHops[0].Relay.Strategy != "fallback" || applied.RouteHops[0].Relay.SourceID != "relays" || applied.Selected != exitID || len(applied.Chain) != 0 {
		t.Fatalf("unexpected saved store after relay route apply: %+v", applied)
	}

	// GET /api/proxy must expose route_hops without leaking credentials.
	w := request(s, "GET", "/api/proxy", s.origin, "", true)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/proxy failed: %d", w.Code)
	}
	for _, secret := range []string{"secret-sub-token", "secret-relay-password", "secret-relay-password-2", p.Auth} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("GET /api/proxy leaked secret %q", secret)
		}
	}
	var view struct {
		RouteHops []struct {
			NodeID         string                   `json:"node_id"`
			Relay          *managedproxy.RelayGroup `json:"relay"`
			Group          string                   `json:"group"`
			CandidateCount int                      `json:"candidate_count"`
		} `json:"route_hops"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || len(view.RouteHops) != 2 {
		t.Fatalf("missing route_hops in GET /api/proxy: %v body=%s", err, w.Body.String())
	}
	if view.RouteHops[0].Relay == nil || view.RouteHops[0].Group != "CAGE-RELAY-0" || view.RouteHops[0].CandidateCount != 2 || view.RouteHops[1].NodeID != exitID {
		t.Fatalf("unexpected route_hops view: %+v", view.RouteHops)
	}

	// Deleting active relay source must be blocked.
	if err := s.changeProxy("delete", proxyInput{ID: "relays"}, nil); err == nil {
		t.Fatal("deleting active relay source succeeded unexpectedly")
	}

	// Refreshing SourceID-backed relay source with rotated node names must succeed
	// while keeping RouteHops and updating Runtime proxy-group members.
	fetchProxySource = func(context.Context, *http.Client, string) ([]byte, string, error) {
		return []byte(`proxies:
  - {name: relay-c, type: http, server: 192.0.2.12, port: 1082, password: rotated}
`), "", nil
	}
	if err := s.changeProxy("refresh", proxyInput{ID: "relays", HostDownload: true}, nil); err != nil {
		t.Fatalf("refresh of active SourceID relay failed: %v", err)
	}
	refreshed, _ := managedproxy.Load(s.profile)
	resolved, err := refreshed.ResolveHops()
	if err != nil || len(resolved[0].Members) != 1 || resolved[0].Members[0] != refreshed.Sources[1].Nodes[0].ID {
		t.Fatalf("refreshed relay source did not update pool dynamically: %+v err=%v", resolved, err)
	}
	rtBytes, err := refreshed.Runtime(s.profile)
	if err != nil {
		t.Fatal(err)
	}
	var rt struct {
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(rtBytes, &rt); err != nil {
		t.Fatal(err)
	}
	if rt.ProxyGroups[0]["name"] != "CAGE-RELAY-0" {
		t.Fatalf("unexpected proxy groups after refresh: %v", rt.ProxyGroups)
	}

	// Explicit NodeIDs relay pool via route API also works, and rollback on failure preserves previous store.
	failStart = true
	if err := s.changeProxy("route", proxyInput{NodeIDs: []string{exitID}}, nil); err == nil {
		t.Fatal("startup failure accepted")
	}
	if afterFail, _ := managedproxy.Load(s.profile); !reflect.DeepEqual(afterFail.RouteHops, refreshed.RouteHops) {
		t.Fatal("failed switch mutated previous RouteHops")
	}
	failStart = false

	// Multi-exit failover on final hop with SourceID relay on hop 0 works via API
	// and blocks deleting sources referenced by exit failover members.
	if err := applied.Import("exits2", "", []byte(`proxies:
  - {name: exit-b, type: socks5, server: 192.0.2.21, port: 1080}
`), "exits2", 0, ""); err != nil {
		t.Fatal(err)
	}
	_ = applied.Save(s.profile)
	exitBID := applied.Sources[len(applied.Sources)-1].Nodes[0].ID
	if err := s.changeProxy("route", proxyInput{
		Hops: []managedproxy.RouteHop{
			{Relay: &managedproxy.RelayGroup{Strategy: managedproxy.RelayStrategyFallback, SourceID: "relays"}},
			{Relay: &managedproxy.RelayGroup{Strategy: managedproxy.RelayStrategyFallback, NodeIDs: []string{exitID, exitBID}}},
		},
	}, nil); err != nil {
		t.Fatalf("multi-exit failover route API failed: %v", err)
	}
	w2 := request(s, "GET", "/api/proxy", s.origin, "", true)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET /api/proxy failed: %d", w2.Code)
	}
	var view2 struct {
		RouteHops []struct {
			Group          string `json:"group"`
			CandidateCount int    `json:"candidate_count"`
		} `json:"route_hops"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &view2); err != nil || len(view2.RouteHops) != 2 {
		t.Fatalf("expected 2 route_hops for dual failover, got err=%v body=%s", err, w2.Body.String())
	}
	if view2.RouteHops[0].Group != "CAGE-RELAY-0" || view2.RouteHops[1].Group != managedproxy.ExitGroupName || view2.RouteHops[1].CandidateCount != 2 {
		t.Fatalf("unexpected dual failover groups: %+v", view2.RouteHops)
	}
	if err := s.changeProxy("delete", proxyInput{ID: "exits2"}, nil); err == nil {
		t.Fatal("deleting source of exit failover member succeeded unexpectedly")
	}

	// select clears both Chain and RouteHops cleanly.
	if err := s.changeProxy("select", proxyInput{NodeID: exitID}, nil); err != nil {
		t.Fatal(err)
	}
	cleared, _ := managedproxy.Load(s.profile)
	if len(cleared.RouteHops) != 0 || len(cleared.Chain) != 0 || cleared.Selected != exitID {
		t.Fatalf("select did not clear RouteHops: %+v", cleared)
	}
}
