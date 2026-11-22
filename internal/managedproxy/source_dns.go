package managedproxy

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ErrSourceNodeDNS marks a source rejected for its node resolver list alone:
// its nodes parsed, so "no importable nodes" would misstate the cause.
var ErrSourceNodeDNS = errors.New("unsupported source node DNS")

type sourceNodeDNSError struct{ error }

func (sourceNodeDNSError) Is(target error) bool { return target == ErrSourceNodeDNS }

// Adopt only the subscription's node resolver list. Its business resolvers,
// policies, hosts, routes and DNS listener remain outside the import boundary.
func subscriptionNodeDNS(data []byte) ([]string, error) {
	var input struct {
		DNS yaml.Node `yaml:"dns"`
	}
	if yaml.Unmarshal(data, &input) != nil || input.DNS.Kind != yaml.MappingNode {
		return nil, nil // Share-link lists have no DNS configuration.
	}
	var dns struct {
		Servers []string `yaml:"proxy-server-nameserver"`
	}
	if input.DNS.Decode(&dns) != nil {
		return nil, sourceNodeDNSError{errors.New("订阅的节点 DNS 需要填写 HTTPS DoH 地址列表")}
	}
	servers, err := validateSourceDNS(dns.Servers)
	if err != nil {
		return nil, sourceNodeDNSError{err}
	}
	return servers, nil
}

func validateSourceDNS(servers []string) ([]string, error) {
	if len(servers) > 4 {
		return nil, errors.New("订阅的节点 DNS 最多支持 4 个 HTTPS DoH 地址")
	}
	var out []string
	local := newLocalServers()
	for i, raw := range servers {
		raw = strings.TrimSpace(raw)
		u, err := url.Parse(raw)
		isDoH := err == nil && u.Scheme == "https"
		isDoT := err == nil && u.Scheme == "tls" && (u.Path == "" || u.Path == "/") && u.RawQuery == ""
		if err != nil || len(raw) > 2048 || (!isDoH && !isDoT) || u.Hostname() == "" || u.User != nil || u.Fragment != "" || local.contains(u.Hostname()) {
			return nil, fmt.Errorf("订阅的第 %d 个节点 DNS 需要远程 HTTPS DoH 地址，不支持用户名、密码或 # 路由参数", i+1)
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("订阅的第 %d 个节点 DNS 端口无效", i+1)
			}
		}
		// Remote DoT (tls://host[:port]) resolvers in third-party Clash
		// subscriptions are validated above and deferred to Cage's own HTTPS DoH
		// resolvers rather than rejecting the subscription or dialing port 853.
		if isDoT {
			continue
		}
		if !slices.Contains(out, raw) {
			out = append(out, raw)
		}
	}
	return out, nil
}

// The bundled core has a separate resolver/cache for proxy server domains.
// Exact policies there cannot alter business DNS or resolver bootstrapping.
// It keys policies by domain, not node/source; reject conflicting ownership
// rather than silently sending another source's queries to this resolver.
func (s Store) sourceDNSPolicies(blocked map[string]string) (map[string][]string, error) {
	policies := map[string][]string{}
	owners := map[string][]string{}
	for _, src := range s.Sources {
		servers, err := validateSourceDNS(src.NodeDNS)
		if err != nil {
			return nil, err
		}
		custom := len(servers) > 0
		if !custom {
			servers = s.NodeResolvers()
		}
		for _, node := range src.Nodes {
			if blocked[node.ID] != "" {
				continue
			}
			host, _ := node.Config["server"].(string)
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
				continue
			}
			if previous, ok := owners[host]; ok && !slices.Equal(previous, servers) {
				return nil, errors.New("多个来源对同一节点域名指定了不同 DNS，无法隔离解析；请统一这些来源的节点 DNS 或移除冲突来源，原配置已保留")
			}
			owners[host] = servers
			if custom {
				if !exactDNSHost(host) {
					return nil, errors.New("使用订阅节点 DNS 时，节点服务器必须是具体域名或 IP，不能包含通配符或匹配规则")
				}
				policies[host] = servers
			}
		}
	}
	return policies, nil
}

func exactDNSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
