package managedproxy

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func sourceDNSInput(host string, servers ...string) string {
	data := fmt.Sprintf("proxies: [{name: node, type: http, server: %q, port: 8080}]\n", host)
	if len(servers) > 0 {
		data += "dns:\n  proxy-server-nameserver:\n"
		for _, server := range servers {
			data += fmt.Sprintf("    - %q\n", server)
		}
	}
	return data
}

func TestSubscriptionNodeDNSPersistsAndRefreshes(t *testing.T) {
	profile := t.TempDir()
	s, _ := Load(profile)
	importSource := func(input string) {
		t.Helper()
		if err := s.Import("source", "", []byte(input), "source", 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	input := sourceDNSInput("node.example.test", "https://resolver.example.test:44443/dns-query?token=private-dns-id")
	input += "  nameserver: [https://unwanted.example/dns-query]\n  nameserver-policy: {'+.*': https://unwanted.example/dns-query}\n  proxy-server-nameserver-policy: {'+.*': https://unwanted.example/dns-query}\n  listen: 0.0.0.0:53\nhosts: {node.example.test: 127.0.0.1}\n"
	importSource(input)
	s.Selected = s.Sources[0].Nodes[0].ID
	if err := s.Save(profile); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Sources[0].NodeDNS, loaded.Sources[0].NodeDNS) || s.Selected != loaded.Selected {
		t.Fatal("persisted source DNS or route changed")
	}
	s = loaded
	if os.Getenv("CAGE_PROXY_INTEGRATION") == "1" {
		if err := Validate(context.Background(), profile, loaded); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want []string) {
		t.Helper()
		wire, err := s.Runtime(profile)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			DNS struct {
				Policy     map[string][]string `yaml:"proxy-server-nameserver-policy"`
				Nameserver []string            `yaml:"nameserver"`
			}
		}
		if err = yaml.Unmarshal(wire, &cfg); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cfg.DNS.Policy["node.example.test"], want) {
			t.Fatal("refresh retained stale or lost source DNS", cfg.DNS.Policy)
		}
		if strings.Contains(string(wire), "unwanted.example") || strings.Contains(string(wire), "listen:") {
			t.Fatal("subscription changed unrelated DNS settings")
		}
	}
	check(s.Sources[0].NodeDNS)
	importSource(sourceDNSInput("node.example.test", "https://second.example.test/dns-query"))
	check([]string{"https://second.example.test/dns-query"})
	before := s.Sources[0]
	if err := s.Import("source", "", []byte(sourceDNSInput("node.example.test", "https://resolver.example.test/dns-query#private-route")), "source", 0, ""); err == nil || strings.Contains(err.Error(), "private-route") {
		t.Fatal("unsafe resolver accepted or leaked", err)
	}
	if !reflect.DeepEqual(before, s.Sources[0]) {
		t.Fatal("failed refresh changed source DNS or nodes")
	}
	importSource(sourceDNSInput("node.example.test"))
	check(nil)
}

func TestSubscriptionNodeDNSIsScopedToExactNodeDomains(t *testing.T) {
	s, _ := Load(t.TempDir())
	s.GuestDNS = []string{"https://9.9.9.9/dns-query"}
	s.BootstrapDNS = []string{"https://223.5.5.5/dns-query"}
	for i, input := range []string{sourceDNSInput("ONE.example.test.", "https://dns-one.example.test/dns-query"), sourceDNSInput("two.example.test", "https://dns-two.example.test/dns-query"), sourceDNSInput("ordinary.example.test"), sourceDNSInput("203.0.113.5", "https://unused.example.test/dns-query")} {
		if err := s.Import(fmt.Sprint(i), "", []byte(input), fmt.Sprint(i), 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	s.Selected = s.Sources[0].Nodes[0].ID
	wire, err := s.Runtime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	yaml.Unmarshal(wire, &cfg)
	dns := cfg["dns"].(map[string]any)
	want := map[string]any{"one.example.test": []any{"https://dns-one.example.test/dns-query"}, "two.example.test": []any{"https://dns-two.example.test/dns-query"}}
	if !reflect.DeepEqual(dns["proxy-server-nameserver-policy"], want) {
		t.Fatal("source DNS escaped exact domains", dns)
	}
	if !reflect.DeepEqual(dns["default-nameserver"], []any{s.BootstrapDNS[0]}) || !reflect.DeepEqual(dns["proxy-server-nameserver"], []any{s.BootstrapDNS[0]}) || !reflect.DeepEqual(dns["nameserver"], []any{s.GuestDNS[0] + "#" + Group}) || dns["nameserver-policy"] != nil {
		t.Fatal("source DNS changed defaults, bootstrap or business DNS")
	}
	if cfg["hosts"] != nil || cfg["external-controller"] != nil {
		t.Fatal("subscription changed runtime boundary")
	}
}

func TestSubscriptionNodeDNSRejectsCrossSourceConflicts(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, other := range []string{"", "https://other.example.test/dns-query"} {
			t.Run(fmt.Sprintf("%v/%s", reverse, other), func(t *testing.T) {
				inputs := []string{sourceDNSInput("shared.example.test", "https://first.example.test/dns-query"), sourceDNSInput("SHARED.example.test.")}
				if other != "" {
					inputs[1] = sourceDNSInput("SHARED.example.test.", other)
				}
				if reverse {
					inputs[0], inputs[1] = inputs[1], inputs[0]
				}
				s, _ := Load(t.TempDir())
				for i, input := range inputs {
					if err := s.Import(fmt.Sprint(i), "", []byte(input), fmt.Sprint(i), 0, ""); err != nil {
						t.Fatal(err)
					}
				}
				s.Selected = s.Sources[0].Nodes[0].ID
				if _, err := s.Runtime(t.TempDir()); err == nil || !strings.Contains(err.Error(), "不同 DNS") || strings.Contains(err.Error(), "example.test") {
					t.Fatal("conflicting sources silently shared DNS or leaked endpoints", err)
				}
			})
		}
	}
}

func TestSubscriptionNodeDNSValidatesUntrustedEndpoints(t *testing.T) {
	for _, server := range []string{"http://resolver.example/dns-query", "system", "tls://localhost:853", "tls://127.0.0.1:853", "tls://user:private-password@resolver.example:853", "tls://resolver.example:853#private-route", "tls://resolver.example:65536", "tls://resolver.example/path", "https://localhost/dns-query", "https://127.0.0.1/dns-query", "https://user:private-password@resolver.example/dns-query", "https://resolver.example/dns-query#private-route", "https://resolver.example:65536/dns-query", "https://resolver.example:0/dns-query"} {
		t.Run(server, func(t *testing.T) {
			s, _ := Load(t.TempDir())
			err := s.Import("source", "", []byte(sourceDNSInput("node.example.test", server)), "source", 0, "")
			if err == nil || strings.Contains(err.Error(), "private-") || len(s.Sources) != 0 {
				t.Fatal("unsafe endpoint accepted, leaked, or changed store", err)
			}
		})
	}
	for _, host := range []string{"+.example.test", "*.example.test", "geosite:cn", "example.test,other.test"} {
		t.Run(host, func(t *testing.T) {
			s, _ := Load(t.TempDir())
			if err := s.Import("source", "", []byte(sourceDNSInput(host, "https://resolver.example/dns-query")), "source", 0, ""); err != nil {
				t.Fatal(err)
			}
			s.Selected = s.Sources[0].Nodes[0].ID
			if _, err := s.Runtime(t.TempDir()); err == nil {
				t.Fatal("node server became a wildcard DNS policy")
			}
		})
	}
	// Equal resolver lists may safely share the exact same node domain.
	s, _ := Load(t.TempDir())
	for _, id := range []string{"a", "b"} {
		if err := s.Import(id, "", []byte(sourceDNSInput("same.example.test", "https://dns.example/dns-query")), id, 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	s.Selected = s.Sources[0].Nodes[0].ID
	if _, err := s.Runtime(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionNodeDNSDefersValidRemoteDoTToDefaultDoH(t *testing.T) {
	t.Run("dot-only", func(t *testing.T) {
		s, _ := Load(t.TempDir())
		s.BootstrapDNS = []string{"https://223.5.5.5/dns-query"}
		if err := s.Import("resip", "", []byte(sourceDNSInput("node.example.test", "tls://223.5.5.5:853", "tls://120.53.53.53:853")), "resip", 0, ""); err != nil {
			t.Fatal(err)
		}
		if len(s.Sources[0].NodeDNS) != 0 {
			t.Fatalf("expected DoT entries to defer cleanly, got %v", s.Sources[0].NodeDNS)
		}
		s.Selected = s.Sources[0].Nodes[0].ID
		wire, err := s.Runtime(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err = yaml.Unmarshal(wire, &cfg); err != nil {
			t.Fatal(err)
		}
		dns := cfg["dns"].(map[string]any)
		if !reflect.DeepEqual(dns["proxy-server-nameserver"], []any{"https://223.5.5.5/dns-query"}) {
			t.Fatalf("expected Cage BootstrapDNS, got %v", dns["proxy-server-nameserver"])
		}
		if policy, _ := dns["proxy-server-nameserver-policy"].(map[string]any); len(policy) != 0 {
			t.Fatalf("expected no DoT override policy, got %v", policy)
		}
	})

	t.Run("mixed-dot-and-doh", func(t *testing.T) {
		s, _ := Load(t.TempDir())
		if err := s.Import("mixed", "", []byte(sourceDNSInput("node.example.test", "tls://223.5.5.5:853", "https://resolver.example.test/dns-query")), "mixed", 0, ""); err != nil {
			t.Fatal(err)
		}
		want := []string{"https://resolver.example.test/dns-query"}
		if !reflect.DeepEqual(s.Sources[0].NodeDNS, want) {
			t.Fatalf("expected %v, got %v", want, s.Sources[0].NodeDNS)
		}
	})

	t.Run("shared-domain-two-sources", func(t *testing.T) {
		s, _ := Load(t.TempDir())
		for _, id := range []string{"resip-vless", "resip-anytls"} {
			if err := s.Import(id, "", []byte(sourceDNSInput("shared.example.test", "tls://223.5.5.5:853")), id, 0, ""); err != nil {
				t.Fatal(err)
			}
		}
		s.Selected = s.Sources[0].Nodes[0].ID
		if _, err := s.Runtime(t.TempDir()); err != nil {
			t.Fatalf("shared node domain across two DoT sources failed: %v", err)
		}
	})
}
