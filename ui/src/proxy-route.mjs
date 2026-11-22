const RELAY_PREFIX = "relay:";
const CUSTOM_PREFIX = "relay-custom:";

export function relayToken(strategy, sourceID) {
  return `${RELAY_PREFIX}${strategy}:${sourceID}`;
}

export function parseRelayToken(token) {
  if (typeof token !== "string" || !token.startsWith(RELAY_PREFIX)) return null;
  const rest = token.slice(RELAY_PREFIX.length);
  const sep = rest.indexOf(":");
  if (sep <= 0) return null;
  const strategy = rest.slice(0, sep);
  const sourceID = rest.slice(sep + 1);
  if ((strategy !== "fallback" && strategy !== "url-test") || !sourceID) return null;
  return { strategy, sourceID };
}

export function customRelayToken(index) {
  return `${CUSTOM_PREFIX}${index}`;
}

export function parseCustomRelayIndex(token) {
  if (typeof token !== "string" || !token.startsWith(CUSTOM_PREFIX)) return null;
  const index = Number(token.slice(CUSTOM_PREFIX.length));
  return Number.isInteger(index) && index >= 0 ? index : null;
}

export function hopsFromProxy(proxy) {
  if (Array.isArray(proxy?.route_hops) && proxy.route_hops.length > 0) {
    return proxy.route_hops.map((hop, index) => {
      if (hop?.node_id) return hop.node_id;
      if (hop?.relay?.source_id) return relayToken(hop.relay.strategy, hop.relay.source_id);
      if (hop?.relay?.node_ids?.length) return customRelayToken(index);
      return "";
    });
  }
  if (Array.isArray(proxy?.route) && proxy.route.length > 0) return proxy.route;
  if (proxy?.selected) return [proxy.selected];
  return [""];
}

export function fixedNodeSet(tokens) {
  const out = new Set();
  for (const tok of tokens || []) {
    if (!tok || parseRelayToken(tok) || parseCustomRelayIndex(tok) !== null) continue;
    out.add(tok);
  }
  return out;
}

export function relayCandidatesForSource(source, usableNodes, fixedIDs) {
  const sourceID = source?.id;
  if (!sourceID) return [];
  const fixed = fixedIDs instanceof Set ? fixedIDs : new Set(fixedIDs || []);
  return (usableNodes || []).filter((n) => n.sourceID === sourceID && !fixed.has(n.id));
}

export function isRouteValid(tokens, sources = [], usableNodes = [], savedHops = []) {
  if (!Array.isArray(tokens) || tokens.length === 0) return false;
  const last = tokens[tokens.length - 1];
  const lastCustomIdx = parseCustomRelayIndex(last);
  if (!last || parseRelayToken(last)) return false;

  const usableIDs = new Set((usableNodes || []).map((n) => n.id));
  if (lastCustomIdx === null && !usableIDs.has(last)) return false;

  const explicitUsed = new Set();
  const fixed = new Set();
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (!tok || parseRelayToken(tok)) continue;
    const customIdx = parseCustomRelayIndex(tok);
    if (customIdx !== null) {
      const custom = savedHops?.[customIdx]?.relay;
      if (!custom?.node_ids || custom.node_ids.length < 2) return false;
      for (const id of custom.node_ids) {
        if (!usableIDs.has(id) || explicitUsed.has(id)) return false;
        explicitUsed.add(id);
      }
      continue;
    }
    if (!usableIDs.has(tok) || explicitUsed.has(tok)) return false;
    explicitUsed.add(tok);
  }

  const usedSources = new Set();
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (!tok) return false;
    const relay = parseRelayToken(tok);
    if (relay) {
      if (i === tokens.length - 1 || usedSources.has(relay.sourceID)) return false;
      const src = (sources || []).find((s) => s.id === relay.sourceID);
      if (!src) return false;
      if (relayCandidatesForSource(src, usableNodes, explicitUsed).length < 1) return false;
      usedSources.add(relay.sourceID);
      continue;
    }
    const customIdx = parseCustomRelayIndex(tok);
    if (customIdx !== null) {
      const custom = savedHops?.[customIdx]?.relay;
      if (!custom?.node_ids || custom.node_ids.length < 2) return false;
      continue;
    }
    if (!usableIDs.has(tok) || fixed.has(tok)) return false;
    fixed.add(tok);
  }
  return true;
}

export function routePayload(tokens, port, savedHops = []) {
  const numericPort = Number(port);
  const hasRelay = (tokens || []).some(
    (tok) => parseRelayToken(tok) !== null || parseCustomRelayIndex(tok) !== null,
  );
  if (!hasRelay) {
    return { node_ids: [...tokens], port: numericPort };
  }
  const hops = tokens.map((tok) => {
    const relay = parseRelayToken(tok);
    if (relay) {
      return { relay: { strategy: relay.strategy, source_id: relay.sourceID } };
    }
    const customIdx = parseCustomRelayIndex(tok);
    if (customIdx !== null && savedHops?.[customIdx]?.relay) {
      const r = savedHops[customIdx].relay;
      return { relay: { strategy: r.strategy, node_ids: [...(r.node_ids || [])] } };
    }
    return { node_id: tok };
  });
  return { hops, port: numericPort };
}

export function activeRelayNodeIDs(proxy) {
  const active = new Set();
  for (const hop of proxy?.route_hops || []) {
    if (hop?.relay && hop?.active_node_id) {
      active.add(hop.active_node_id);
    }
  }
  return active;
}
