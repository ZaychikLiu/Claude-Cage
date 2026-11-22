package managedproxy

import (
	"errors"
	"fmt"
	"maps"
)

const (
	// RelayStrategyFallback switches to backup relay nodes when the active relay fails.
	RelayStrategyFallback = "fallback"
	// RelayStrategyURLTest picks the lowest-latency relay node in the group.
	RelayStrategyURLTest = "url-test"

	RelayGroupPrefix      = "CAGE-RELAY-"
	MaxRelayPoolNodes     = 300
	RelayHealthCheckURL   = "https://www.gstatic.com/generate_204"
	RelayCheckIntervalSec = 120
	RelayCheckTimeoutMs   = 5000
	RelayURLTestTolerance = 50
)

// relayHealthCheckSettings allows deterministic integration tests with a local
// HTTP health check server while keeping production defaults fixed and safe.
type relayHealthCheckSettings struct {
	url      string
	interval int
	timeout  int
	lazy     bool
}

func defaultRelayHealthCheckSettings() relayHealthCheckSettings {
	return relayHealthCheckSettings{
		url:      RelayHealthCheckURL,
		interval: RelayCheckIntervalSec,
		timeout:  RelayCheckTimeoutMs,
		lazy:     true,
	}
}

var relayCheckConfig = defaultRelayHealthCheckSettings

// RelayGroup defines an automatic-switching pool of intermediate relay nodes.
// Final exit hops must remain single pinned nodes and never use a RelayGroup.
type RelayGroup struct {
	Strategy string   `json:"strategy"`
	SourceID string   `json:"source_id,omitempty"`
	NodeIDs  []string `json:"node_ids,omitempty"`
}

// RouteHop represents one hop in an explicit chained proxy route.
// Exactly one of NodeID (pinned single node) or Relay (auto-switching relay pool)
// must be set. The final hop must always be a pinned NodeID.
type RouteHop struct {
	NodeID string      `json:"node_id,omitempty"`
	Relay  *RelayGroup `json:"relay,omitempty"`
}

// ResolvedHop is the runtime-validated expansion of a RouteHop.
type ResolvedHop struct {
	Index     int
	NodeID    string
	Relay     *RelayGroup
	GroupName string
	Members   []string
}

// RelayGroupName returns the deterministic Mihomo proxy-group name for hop index.
func RelayGroupName(index int) string {
	return fmt.Sprintf("%s%d", RelayGroupPrefix, index)
}

func (r RelayGroup) ValidStrategy() bool {
	return r.Strategy == RelayStrategyFallback || r.Strategy == RelayStrategyURLTest
}

func (h ResolvedHop) runtimeTarget() string {
	if h.Relay != nil {
		return h.GroupName
	}
	return h.NodeID
}

func (h ResolvedHop) proxyGroupConfig() map[string]any {
	cfg := relayCheckConfig()
	group := map[string]any{
		"name":     h.GroupName,
		"type":     h.Relay.Strategy,
		"proxies":  append([]string(nil), h.Members...),
		"url":      cfg.url,
		"interval": cfg.interval,
		"timeout":  cfg.timeout,
		"lazy":     cfg.lazy,
	}
	if h.Relay.Strategy == RelayStrategyURLTest {
		group["tolerance"] = RelayURLTestTolerance
	}
	return group
}

// ResolveHops resolves the store's active route into concrete hops from entry to
// exit. Single-node and legacy chains return one ResolvedHop per node; chains
// with auto-switching relay pools expand each pool against non-blocked nodes.
func (s Store) ResolveHops() ([]ResolvedHop, error) {
	return s.resolveHops(s.BlockedNodes())
}

func (s Store) resolveHops(blocked map[string]string) ([]ResolvedHop, error) {
	if len(s.RouteHops) == 0 {
		route, err := s.route(blocked)
		resolved := make([]ResolvedHop, 0, len(route))
		for i, id := range route {
			resolved = append(resolved, ResolvedHop{
				Index:   i,
				NodeID:  id,
				Members: []string{id},
			})
		}
		return resolved, err
	}

	if _, ok := s.Find(s.Selected); !ok {
		return nil, errors.New("请先选择有效的最终出口")
	}
	if len(s.RouteHops) < 2 {
		return nil, errors.New("中转代理链至少需要包含中转与最终出口")
	}
	last := s.RouteHops[len(s.RouteHops)-1]
	if last.Relay != nil || last.NodeID == "" {
		return nil, errors.New("最终出口必须是单个固定节点")
	}
	if last.NodeID != s.Selected {
		return nil, errors.New("代理链与最终出口不一致，请重新配置代理")
	}

	pinnedFixed := make(map[string]bool, len(s.RouteHops))
	for i, hop := range s.RouteHops {
		hasNode := hop.NodeID != ""
		hasRelay := hop.Relay != nil
		if hasNode == hasRelay {
			return nil, errors.New("代理链每一跳只能指定单个节点或一个中转组")
		}
		if hasRelay && i == len(s.RouteHops)-1 {
			return nil, errors.New("最终出口必须是单个固定节点")
		}
		if hasNode {
			if _, ok := s.Find(hop.NodeID); !ok {
				return nil, errors.New("代理链中的节点已被移除，请重新选择；原配置已保留")
			}
			if pinnedFixed[hop.NodeID] {
				return nil, errors.New("代理链不能重复使用同一个节点")
			}
			pinnedFixed[hop.NodeID] = true
		}
	}

	usedNodes := maps.Clone(pinnedFixed)
	usedRelaySources := map[string]bool{}
	resolved := make([]ResolvedHop, 0, len(s.RouteHops))

	for i, hop := range s.RouteHops {
		if hop.NodeID != "" {
			if blocked[hop.NodeID] != "" {
				n, _ := s.Find(hop.NodeID)
				return nil, fmt.Errorf("节点 %q 需要迁移：%w", n.Name, ErrLocalProxyNode)
			}
			resolved = append(resolved, ResolvedHop{
				Index:   i,
				NodeID:  hop.NodeID,
				Members: []string{hop.NodeID},
			})
			continue
		}

		relay := hop.Relay
		if !relay.ValidStrategy() {
			return nil, errors.New("中转策略无效，仅支持 fallback 或 url-test")
		}
		hasSource := relay.SourceID != ""
		hasNodes := len(relay.NodeIDs) > 0
		if hasSource == hasNodes {
			return nil, errors.New("中转组必须二选一指定订阅来源或节点列表")
		}

		var members []string
		var relayCopy RelayGroup
		relayCopy.Strategy = relay.Strategy

		if hasSource {
			if usedRelaySources[relay.SourceID] {
				return nil, errors.New("多个中转跳不能重复使用同一个订阅来源")
			}
			usedRelaySources[relay.SourceID] = true
			src, ok := s.findSource(relay.SourceID)
			if !ok {
				return nil, errors.New("中转订阅来源不存在，请重新配置")
			}
			relayCopy.SourceID = src.ID
			sawBlocked := false
			for _, n := range src.Nodes {
				if pinnedFixed[n.ID] || usedNodes[n.ID] {
					continue
				}
				if blocked[n.ID] != "" {
					sawBlocked = true
					continue
				}
				usedNodes[n.ID] = true
				members = append(members, n.ID)
				if len(members) > MaxRelayPoolNodes {
					return nil, fmt.Errorf("中转组最多包含 %d 个节点", MaxRelayPoolNodes)
				}
			}
			if len(members) == 0 {
				if sawBlocked && len(src.Nodes) > 0 {
					return nil, fmt.Errorf("中转来源 %q 仅包含本机代理节点：%w", src.Name, ErrLocalProxyNode)
				}
				return nil, fmt.Errorf("中转来源 %q 没有可用的中转节点", src.Name)
			}
		} else {
			if len(relay.NodeIDs) < 2 {
				return nil, errors.New("自定义中转节点列表至少需要 2 个节点")
			}
			if len(relay.NodeIDs) > MaxRelayPoolNodes {
				return nil, fmt.Errorf("中转组最多包含 %d 个节点", MaxRelayPoolNodes)
			}
			relayCopy.NodeIDs = append([]string(nil), relay.NodeIDs...)
			seenLocal := map[string]bool{}
			for _, nid := range relay.NodeIDs {
				if nid == "" {
					return nil, errors.New("中转节点列表包含空节点 ID")
				}
				n, ok := s.Find(nid)
				if !ok {
					return nil, errors.New("中转组中的节点已被移除，请重新选择；原配置已保留")
				}
				if seenLocal[nid] || usedNodes[nid] {
					return nil, errors.New("代理链不能重复使用同一个节点")
				}
				if blocked[nid] != "" {
					return nil, fmt.Errorf("节点 %q 需要迁移：%w", n.Name, ErrLocalProxyNode)
				}
				seenLocal[nid] = true
				usedNodes[nid] = true
				members = append(members, nid)
			}
		}

		resolved = append(resolved, ResolvedHop{
			Index:     i,
			Relay:     &relayCopy,
			GroupName: RelayGroupName(i),
			Members:   members,
		})
	}

	return resolved, nil
}

func (s Store) findSource(id string) (Source, bool) {
	for _, src := range s.Sources {
		if src.ID == id {
			return src, true
		}
	}
	return Source{}, false
}

// RouteHopsReferencesSource reports whether active RouteHops depend on sourceID
// (either as a dynamic relay source or via any pinned fixed/relay node ID).
func (s Store) RouteHopsReferencesSource(src Source) bool {
	if len(s.RouteHops) == 0 {
		return false
	}
	inSource := make(map[string]bool, len(src.Nodes))
	for _, n := range src.Nodes {
		inSource[n.ID] = true
	}
	for _, hop := range s.RouteHops {
		if hop.NodeID != "" && inSource[hop.NodeID] {
			return true
		}
		if hop.Relay != nil {
			if hop.Relay.SourceID == src.ID {
				return true
			}
			for _, nid := range hop.Relay.NodeIDs {
				if inSource[nid] {
					return true
				}
			}
		}
	}
	return false
}

func cloneRouteHops(hops []RouteHop) []RouteHop {
	if len(hops) == 0 {
		return nil
	}
	out := make([]RouteHop, len(hops))
	for i, hop := range hops {
		out[i].NodeID = hop.NodeID
		if hop.Relay != nil {
			cp := *hop.Relay
			if len(hop.Relay.NodeIDs) > 0 {
				cp.NodeIDs = append([]string(nil), hop.Relay.NodeIDs...)
			}
			out[i].Relay = &cp
		}
	}
	return out
}

func allHopsFixed(hops []RouteHop) ([]string, bool) {
	ids := make([]string, 0, len(hops))
	for _, hop := range hops {
		if hop.Relay != nil || hop.NodeID == "" {
			return nil, false
		}
		ids = append(ids, hop.NodeID)
	}
	return ids, len(ids) > 0
}

// SetRouteHops updates the store's Selected, Chain, and RouteHops fields
// consistently for either fixed chains or chains containing relay pools,
// and validates the resulting route against the current store.
func (s *Store) SetRouteHops(hops []RouteHop) error {
	if len(hops) == 0 {
		return errors.New("请至少选择一个最终出口")
	}
	last := hops[len(hops)-1]
	if last.Relay != nil || last.NodeID == "" {
		return errors.New("最终出口必须是单个固定节点")
	}
	if len(hops) == 1 {
		s.Selected = last.NodeID
		s.Chain = nil
		s.RouteHops = nil
		_, err := s.ResolveHops()
		return err
	}
	if fixed, ok := allHopsFixed(hops); ok {
		s.Chain = fixed
		s.Selected = last.NodeID
		s.RouteHops = nil
		_, err := s.ResolveHops()
		return err
	}
	s.RouteHops = cloneRouteHops(hops)
	s.Chain = nil
	s.Selected = last.NodeID
	_, err := s.ResolveHops()
	return err
}
