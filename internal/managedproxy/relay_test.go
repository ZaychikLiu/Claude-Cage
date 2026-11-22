package managedproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestRelayGroupResolveRuntimeAndRefresh(t *testing.T) {
	profile := t.TempDir()
	s, _ := Load(profile)
	if err := s.Import("airport", "", []byte(`proxies:
  - {name: hop-a, type: socks5, server: 192.0.2.10, port: 1080}
  - {name: hop-b, type: socks5, server: 192.0.2.11, port: 1081, dialer-proxy: hop-a}
  - {name: ipv6-hop, type: socks5, server: "[2001:db8::2]", port: 1082}
`), "airport", 0, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Import("home", "", []byte(`proxies:
  - {name: home-exit, type: socks5, server: 198.51.100.20, port: 2080}
`), "home", 0, ""); err != nil {
		t.Fatal(err)
	}
	exit := s.Sources[1].Nodes[0].ID
	err := s.SetRouteHops([]RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyFallback, SourceID: "airport"}},
		{NodeID: exit},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(profile); err != nil {
		t.Fatal(err)
	}

	resolved, err := s.ResolveHops()
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].GroupName != "CAGE-RELAY-0" || len(resolved[0].Members) != 3 || resolved[1].NodeID != exit {
		t.Fatalf("unexpected resolved hops: %+v", resolved)
	}

	data, err := s.Runtime(profile)
	if err != nil {
		t.Fatal(err)
	}
	var rt struct {
		IPv6        bool             `yaml:"ipv6"`
		Proxies     []map[string]any `yaml:"proxies"`
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
		Rules       []string         `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &rt); err != nil {
		t.Fatal(err)
	}
	if !rt.IPv6 {
		t.Fatal("expected ipv6=true when a relay pool member uses a literal IPv6 server")
	}
	var foundRelayGroup, foundMainGroup bool
	for _, g := range rt.ProxyGroups {
		if g["name"] == "CAGE-RELAY-0" {
			foundRelayGroup = true
			if g["type"] != "fallback" {
				t.Fatalf("expected fallback strategy, got %v", g["type"])
			}
			proxies, _ := g["proxies"].([]any)
			if len(proxies) != 3 {
				t.Fatalf("expected 3 relay members, got %v", proxies)
			}
		}
		if g["name"] == Group {
			foundMainGroup = true
			proxies, _ := g["proxies"].([]any)
			if len(proxies) != 1 || proxies[0] != exit {
				t.Fatalf("expected CAGE group pinned to exit %q, got %v", exit, proxies)
			}
		}
	}
	if !foundRelayGroup || !foundMainGroup {
		t.Fatalf("missing proxy groups: relay=%v main=%v", foundRelayGroup, foundMainGroup)
	}
	byName := map[string]map[string]any{}
	for _, p := range rt.Proxies {
		name, _ := p["name"].(string)
		byName[name] = p
	}
	// Exit must dial through CAGE-RELAY-0; Hop 0 members must clear imported dialers.
	if byName[exit]["dialer-proxy"] != "CAGE-RELAY-0" {
		t.Fatalf("exit dialer-proxy = %v, want CAGE-RELAY-0", byName[exit]["dialer-proxy"])
	}
	hopB := s.Sources[0].Nodes[1].ID
	if byName[hopB]["dialer-proxy"] != nil {
		t.Fatalf("hop 0 relay member retained stale dialer-proxy: %v", byName[hopB]["dialer-proxy"])
	}
	// Named account clone for hopB must still retain its imported dialer.
	routeHopB, ok := byName["route-"+hopB]
	if !ok || routeHopB["dialer-proxy"] != s.Sources[0].Nodes[0].ID {
		t.Fatalf("expected account clone route-%s to retain imported dialer, got %v", hopB, routeHopB)
	}

	// Refreshing a SourceID-backed relay source may rename/drop/add relay nodes
	// as long as >= 1 usable relay node remains.
	if err := s.Import("airport", "", []byte(`proxies:
  - {name: hop-c, type: socks5, server: 192.0.2.12, port: 1083}
`), "airport", 0, ""); err != nil {
		t.Fatalf("refresh of SourceID relay should allow rotating nodes: %v", err)
	}
	resolvedAfter, err := s.ResolveHops()
	if err != nil || len(resolvedAfter[0].Members) != 1 {
		t.Fatalf("expected 1 dynamically updated relay member, got %+v err=%v", resolvedAfter, err)
	}

	// Refreshing the exit source to drop the pinned exit must still be rejected.
	if err := s.Import("home", "", []byte(`proxies:
  - {name: other-exit, type: socks5, server: 198.51.100.21, port: 2081}
`), "home", 0, ""); err == nil {
		t.Fatal("expected error when refresh drops pinned exit node")
	}

	// Refreshing SourceID relay to leave 0 usable nodes must be rejected.
	if err := s.Import("airport", "", []byte(`proxies:
  - {name: local-only, type: socks5, server: 127.0.0.1, port: 1080}
`), "airport", 0, ""); err == nil {
		t.Fatal("expected error when refresh leaves 0 usable relay nodes")
	}
}

func TestRelayGroupRejectsInvalidShapesAndExcludesExitFromSource(t *testing.T) {
	profile := t.TempDir()
	s, _ := Load(profile)
	if err := s.Import("mixed", "", []byte(`proxies:
  - {name: r1, type: socks5, server: 192.0.2.1, port: 1080}
  - {name: r2, type: socks5, server: 192.0.2.2, port: 1080}
  - {name: ex, type: socks5, server: 192.0.2.3, port: 1080}
  - {name: loc, type: socks5, server: legacy.example, port: 1080}
`), "mixed", 0, ""); err != nil {
		t.Fatal(err)
	}
	nodes := s.Sources[0].Nodes
	nodes[3].Config["server"] = "127.0.0.1"
	r1, r2, ex, loc := nodes[0].ID, nodes[1].ID, nodes[2].ID, nodes[3].ID

	// Using same source for relay while picking one of its nodes as pinned exit:
	// ex and loc (blocked) must both be excluded, leaving [r1, r2].
	if err := s.SetRouteHops([]RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyURLTest, SourceID: "mixed"}},
		{NodeID: ex},
	}); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveHops()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resolved[0].Members, []string{r1, r2}) {
		t.Fatalf("expected relay members [%s %s] (excluding exit and local), got %v", r1, r2, resolved[0].Members)
	}
	data, err := s.Runtime(profile)
	if err != nil {
		t.Fatal(err)
	}
	var rt struct {
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(data, &rt); err != nil {
		t.Fatal(err)
	}
	if rt.ProxyGroups[0]["type"] != "url-test" || rt.ProxyGroups[0]["tolerance"] != RelayURLTestTolerance {
		t.Fatalf("unexpected url-test group config: %v", rt.ProxyGroups[0])
	}

	// Explicit NodeIDs pool works too, and blocks local nodes inside NodeIDs.
	if err := s.SetRouteHops([]RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyFallback, NodeIDs: []string{r1, r2}}},
		{NodeID: ex},
	}); err != nil {
		t.Fatal(err)
	}

	// Local node in explicit NodeIDs must surface ErrLocalProxyNode.
	sBadLocal := s
	sBadLocal.RouteHops = []RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyFallback, NodeIDs: []string{r1, loc}}},
		{NodeID: ex},
	}
	if _, err := sBadLocal.Route(); !errors.Is(err, ErrLocalProxyNode) {
		t.Fatalf("expected ErrLocalProxyNode, got %v", err)
	}

	// Invalid shapes must all be rejected.
	invalidCases := []struct {
		name string
		hops []RouteHop
	}{
		{"empty", nil},
		{"relay-as-exit", []RouteHop{{NodeID: r1}, {Relay: &RelayGroup{Strategy: RelayStrategyFallback, SourceID: "mixed"}}}},
		{"bad-strategy", []RouteHop{{Relay: &RelayGroup{Strategy: "select", SourceID: "mixed"}}, {NodeID: ex}}},
		{"both-source-and-nodes", []RouteHop{{Relay: &RelayGroup{Strategy: RelayStrategyFallback, SourceID: "mixed", NodeIDs: []string{r1, r2}}}, {NodeID: ex}}},
		{"neither-source-nor-nodes", []RouteHop{{Relay: &RelayGroup{Strategy: RelayStrategyFallback}}, {NodeID: ex}}},
		{"duplicate-source", []RouteHop{{Relay: &RelayGroup{Strategy: RelayStrategyFallback, SourceID: "mixed"}}, {Relay: &RelayGroup{Strategy: RelayStrategyURLTest, SourceID: "mixed"}}, {NodeID: ex}}},
		{"single-explicit-node", []RouteHop{{Relay: &RelayGroup{Strategy: RelayStrategyFallback, NodeIDs: []string{r1}}}, {NodeID: ex}}},
		{"exit-in-explicit-relay", []RouteHop{{Relay: &RelayGroup{Strategy: RelayStrategyFallback, NodeIDs: []string{r1, ex}}}, {NodeID: ex}}},
	}
	for _, tc := range invalidCases {
		clone := s
		if err := clone.SetRouteHops(tc.hops); err == nil {
			t.Fatalf("case %q unexpectedly succeeded", tc.name)
		}
	}
}

func TestRelayBindInterfaceOnlyAppliesToHop0(t *testing.T) {
	profile := t.TempDir()
	s, _ := Load(profile)
	if err := s.Import("src", "", []byte(`proxies:
  - {name: r1, type: socks5, server: 100.64.0.10, port: 1080}
  - {name: r2, type: socks5, server: 192.0.2.2, port: 1080}
  - {name: ex, type: socks5, server: 100.64.0.20, port: 1080}
`), "src", 0, ""); err != nil {
		t.Fatal(err)
	}
	r1, r2, ex := s.Sources[0].Nodes[0].ID, s.Sources[0].Nodes[1].ID, s.Sources[0].Nodes[2].ID
	if err := s.SetRouteHops([]RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyFallback, SourceID: "src"}},
		{NodeID: ex},
	}); err != nil {
		t.Fatal(err)
	}
	oldIfaces, oldProbe := listHostInterfaces, probeRouteSourceIP
	t.Cleanup(func() { listHostInterfaces, probeRouteSourceIP = oldIfaces, oldProbe })
	listHostInterfaces = func() ([]hostInterface, error) {
		return []hostInterface{
			{name: "en0", prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")}},
			{name: "utun9", prefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}},
		}, nil
	}
	probeRouteSourceIP = func(dst netip.Addr) (netip.Addr, bool) {
		if isTailscaleAddr(dst) {
			return netip.MustParseAddr("100.64.0.1"), true
		}
		return netip.MustParseAddr("192.168.1.2"), true
	}
	raw, err := s.Runtime(profile)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindInterface(raw, "en0")
	if err != nil {
		t.Fatal(err)
	}
	var rt struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(bound, &rt); err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]any{}
	for _, p := range rt.Proxies {
		name, _ := p["name"].(string)
		byName[name] = p
	}
	if byName[r1]["interface-name"] != "utun9" {
		t.Fatalf("expected Tailscale hop0 relay member %s bound to utun9, got %v", r1, byName[r1]["interface-name"])
	}
	if byName[r2]["interface-name"] != nil {
		t.Fatalf("expected public hop0 relay member %s to inherit physical interface, got %v", r2, byName[r2]["interface-name"])
	}
	if byName[ex]["interface-name"] != nil {
		t.Fatalf("chained exit %s must not receive direct interface-name override, got %v", ex, byName[ex]["interface-name"])
	}
}

func findTestMihomo(t *testing.T) string {
	t.Helper()
	if p, err := CorePath(); err == nil {
		return p
	}
	name := "mihomo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	candidate := filepath.Join("..", "..", "_output", "proxy-core", name)
	if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() && (runtime.GOOS == "windows" || st.Mode()&0111 != 0) {
		abs, err := filepath.Abs(candidate)
		if err == nil {
			return abs
		}
	}
	t.Skip("requires bundled mihomo at _output/proxy-core/" + name)
	return ""
}

// startTestSOCKS5 starts a minimal no-auth SOCKS5 TCP CONNECT relay that counts
// forwarded connections and closes active connections on teardown.
func startTestSOCKS5(t *testing.T, hits *atomic.Int64) (port string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	shutdown := func() {
		cancel()
		_ = ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}
	go func() {
		<-ctx.Done()
		shutdown()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			go func(c net.Conn) {
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
				}()
				handleSOCKS5Conn(ctx, c, hits)
			}(conn)
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	t.Cleanup(shutdown)
	return port, shutdown
}

func handleSOCKS5Conn(ctx context.Context, c net.Conn, hits *atomic.Int64) {
	defer c.Close()
	r := bufio.NewReader(c)
	ver, err := r.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nmethods, err := r.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil || hdr[1] != 0x01 {
		return
	}
	var host string
	switch hdr[3] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		l, err := r.ReadByte()
		if err != nil {
			return
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		host = string(buf)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		return
	}
	var pbuf [2]byte
	if _, err := io.ReadFull(r, pbuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pbuf[:])
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	hits.Add(1)
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(upstream, r)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(c, upstream)
}

func TestRelayGroupRealMihomoValidationAndFailover(t *testing.T) {
	core := findTestMihomo(t)

	var targetHits, relay1Hits, relay2Hits, exitHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "reached-via-exit")
	}))
	t.Cleanup(target.Close)

	oldCheck := relayCheckConfig
	relayCheckConfig = func() relayHealthCheckSettings {
		return relayHealthCheckSettings{
			url:      target.URL + "/generate_204",
			interval: 1,
			timeout:  1000,
			lazy:     false,
		}
	}
	t.Cleanup(func() { relayCheckConfig = oldCheck })

	r1Port, closeRelay1 := startTestSOCKS5(t, &relay1Hits)
	r2Port, closeRelay2 := startTestSOCKS5(t, &relay2Hits)
	exPort, _ := startTestSOCKS5(t, &exitHits)

	profile := t.TempDir()
	store, err := Load(profile)
	if err != nil {
		t.Fatal(err)
	}
	// Reserve an ephemeral port for Mihomo mixed-port.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	store.Port = ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	if err := store.Import("relays", "", []byte(fmt.Sprintf(`proxies:
  - {name: relay1, type: socks5, server: relay1.example.test, port: %s}
  - {name: relay2, type: socks5, server: relay2.example.test, port: %s}
`, r1Port, r2Port)), "relays", 0, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Import("exit", "", []byte(fmt.Sprintf(`proxies:
  - {name: exit-node, type: socks5, server: exit.example.test, port: %s}
`, exPort)), "exit", 0, ""); err != nil {
		t.Fatal(err)
	}
	exitID := store.Sources[1].Nodes[0].ID
	r1ID := store.Sources[0].Nodes[0].ID
	r2ID := store.Sources[0].Nodes[1].ID

	// Validate both url-test and fallback YAML with real `mihomo -t`.
	if err := store.SetRouteHops([]RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyURLTest, SourceID: "relays"}},
		{NodeID: exitID},
	}); err != nil {
		t.Fatal(err)
	}
	utYAML, err := store.Runtime(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWithCoreBinary(t, core, profile, utYAML); err != nil {
		t.Fatalf("url-test YAML failed real mihomo -t validation: %v", err)
	}

	if err := store.SetRouteHops([]RouteHop{
		{Relay: &RelayGroup{Strategy: RelayStrategyFallback, SourceID: "relays"}},
		{NodeID: exitID},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(profile); err != nil {
		t.Fatal(err)
	}
	runtimeBytes, err := store.Runtime(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWithCoreBinary(t, core, profile, runtimeBytes); err != nil {
		t.Fatalf("fallback YAML failed real mihomo -t validation: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}

	var loopback string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			loopback = iface.Name
			break
		}
	}
	runtimeBytes, err = BindInterface(runtimeBytes, loopback)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(Dir(profile), "config.yaml")
	if err := Write(configPath, runtimeBytes); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(Socket(profile)), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(Socket(profile))) })

	logFile, err := os.Create(filepath.Join(profile, "mihomo.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(core, "-d", Dir(profile), "-f", configPath)
	cmd.Env, cmd.Stdout, cmd.Stderr = coreEnvironment(Dir(profile)), logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = logFile.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for !Running(ctx, profile, store) {
		if ctx.Err() != nil {
			t.Fatalf("mihomo core did not become ready: stage=%s", RunningStage(context.Background(), profile, store))
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Now point the running core in memory to our local test SOCKS5 servers via PUT /configs,
	// leaving the on-disk config.yaml bound to non-local hostnames just like websocket_core_test.go.
	liveConfig := string(runtimeBytes)
	liveConfig = strings.ReplaceAll(liveConfig, "relay1.example.test", "127.0.0.1")
	liveConfig = strings.ReplaceAll(liveConfig, "relay2.example.test", "127.0.0.1")
	liveConfig = strings.ReplaceAll(liveConfig, "exit.example.test", "127.0.0.1")
	if err := API(ctx, profile, "PUT", "/configs", map[string]string{"payload": liveConfig}, nil); err != nil {
		t.Fatal(err)
	}

	proxyURL, _ := url.Parse(store.Endpoint())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
		Timeout: 4 * time.Second,
	}

	// Wait until CAGE-RELAY-0 settles on relay1 (first healthy in fallback list).
	waitRelayNow(t, ctx, profile, r1ID)
	body := mustHTTPGet(t, client, target.URL+"/one")
	if body != "reached-via-exit" || relay1Hits.Load() == 0 || exitHits.Load() == 0 || targetHits.Load() != 1 {
		t.Fatalf("initial hop via relay1 failed: body=%q r1=%d r2=%d exit=%d target=%d", body, relay1Hits.Load(), relay2Hits.Load(), exitHits.Load(), targetHits.Load())
	}

	// Tear down relay1: mihomo fallback group must fail over to relay2 automatically while keeping exit unchanged.
	closeRelay1()
	r1Before := relay1Hits.Load()
	exitBefore := exitHits.Load()
	waitRelayNow(t, ctx, profile, r2ID)

	body = mustHTTPGet(t, client, target.URL+"/two")
	if body != "reached-via-exit" || relay1Hits.Load() != r1Before || relay2Hits.Load() == 0 || exitHits.Load() <= exitBefore || targetHits.Load() != 2 {
		t.Fatalf("failover to relay2 failed: body=%q r1=%d->%d r2=%d exit=%d->%d target=%d", body, r1Before, relay1Hits.Load(), relay2Hits.Load(), exitBefore, exitHits.Load(), targetHits.Load())
	}

	// Tear down relay2 as well: mihomo must fail closed and NEVER hit target directly.
	closeRelay2()
	time.Sleep(1500 * time.Millisecond)
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/three", nil)
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected fail-closed error when all relays are down, got HTTP %d", resp.StatusCode)
	}
	if targetHits.Load() != 2 {
		t.Fatalf("direct connection reached target after all relays closed (hits=%d)", targetHits.Load())
	}
}

func validateWithCoreBinary(t *testing.T, core, profile string, yamlBytes []byte) error {
	t.Helper()
	dir := Dir(profile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "validate-relay.yaml")
	if err := os.WriteFile(tmp, yamlBytes, 0600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	cmd := exec.Command(core, "-t", "-d", dir, "-f", tmp)
	cmd.Env = coreEnvironment(dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

func waitRelayNow(t *testing.T, ctx context.Context, profile, want string) {
	t.Helper()
	for {
		var group struct {
			Now     string   `json:"now"`
			History []any    `json:"history"`
			All     []string `json:"all"`
		}
		if err := API(ctx, profile, "GET", "/proxies/CAGE-RELAY-0", nil, &group); err == nil {
			if group.Now == want {
				return
			}
			_ = slices.Contains(group.All, want)
		}
		if ctx.Err() != nil {
			t.Fatalf("timed out waiting for CAGE-RELAY-0 to select %q (last now=%q)", want, group.Now)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func mustHTTPGet(t *testing.T, client *http.Client, targetURL string) string {
	t.Helper()
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET %s failed: %v", targetURL, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d err=%v body=%q", targetURL, resp.StatusCode, err, string(b))
	}
	return string(b)
}
