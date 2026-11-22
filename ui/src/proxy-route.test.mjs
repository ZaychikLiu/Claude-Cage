import assert from "node:assert/strict";
import test from "node:test";
import {
  activeRelayNodeIDs,
  hopsFromProxy,
  isRouteValid,
  parseCustomRelayIndex,
  parseRelayToken,
  relayCandidatesForSource,
  relayToken,
  routePayload,
} from "./proxy-route.mjs";

const sources = [
  { id: "src-relay", name: "RelaySrc" },
  { id: "src-exit", name: "ExitSrc" },
  { id: "src-single", name: "SingleSrc" },
];

const usableNodes = [
  { id: "r1", name: "Relay 1", sourceID: "src-relay" },
  { id: "r2", name: "Relay 2", sourceID: "src-relay" },
  { id: "e1", name: "Exit 1", sourceID: "src-exit" },
  { id: "s1", name: "Only 1", sourceID: "src-single" },
];

test("relayToken and parseRelayToken round-trip valid strategies", () => {
  const fb = relayToken("fallback", "src-relay");
  assert.deepEqual(parseRelayToken(fb), { strategy: "fallback", sourceID: "src-relay" });
  const ut = relayToken("url-test", "src:with:colons");
  assert.deepEqual(parseRelayToken(ut), { strategy: "url-test", sourceID: "src:with:colons" });
  assert.equal(parseRelayToken("plain-node-id"), null);
  assert.equal(parseRelayToken("relay:unknown:src"), null);
  assert.equal(parseCustomRelayIndex("relay-custom:0"), 0);
  assert.equal(parseCustomRelayIndex("plain"), null);
});

test("hopsFromProxy prefers route_hops and encodes fixed and relay hops", () => {
  const tokens = hopsFromProxy({
    selected: "e1",
    route_hops: [
      { relay: { strategy: "fallback", source_id: "src-relay" }, active_node_id: "r2" },
      { node_id: "e1" },
    ],
  });
  assert.deepEqual(tokens, ["relay:fallback:src-relay", "e1"]);
  assert.deepEqual([...activeRelayNodeIDs({
    route_hops: [
      { relay: { strategy: "fallback", source_id: "src-relay" }, active_node_id: "r2" },
      { node_id: "e1" },
    ],
  })], ["r2"]);
  assert.deepEqual(hopsFromProxy({ route: ["r1", "e1"], selected: "e1" }), ["r1", "e1"]);
  assert.deepEqual(hopsFromProxy({ selected: "e1" }), ["e1"]);
});

test("isRouteValid accepts relay sources with usable non-exit nodes and rejects invalid shapes", () => {
  assert.equal(isRouteValid(["relay:fallback:src-relay", "e1"], sources, usableNodes), true);
  assert.equal(isRouteValid(["relay:url-test:src-relay", "e1"], sources, usableNodes), true);
  // Relay hop cannot be the final exit.
  assert.equal(isRouteValid(["e1", "relay:fallback:src-relay"], sources, usableNodes), false);
  // Duplicate relay sources rejected.
  assert.equal(
    isRouteValid(["relay:fallback:src-relay", "relay:url-test:src-relay", "e1"], sources, usableNodes),
    false,
  );
  // Source whose only node is chosen as the exit cannot serve as a relay hop.
  assert.equal(isRouteValid(["relay:fallback:src-single", "s1"], sources, usableNodes), false);
  // Final hop with custom explicit NodeIDs is valid for multi-exit failover, while excluding duplicates.
  assert.equal(
    isRouteValid(
      ["relay:fallback:src-relay", "relay-custom:1"],
      sources,
      usableNodes,
      [
        { relay: { strategy: "fallback", source_id: "src-relay" } },
        { relay: { strategy: "fallback", node_ids: ["e1", "s1"] } },
      ],
    ),
    true,
  );
  assert.equal(
    isRouteValid(
      ["r1", "relay-custom:1"],
      sources,
      usableNodes,
      [
        { node_id: "r1" },
        { relay: { strategy: "fallback", node_ids: ["r1", "e1"] } },
      ],
    ),
    false,
  );
  // Relay candidates exclude fixed nodes in the route.
  assert.equal(relayCandidatesForSource(sources[0], usableNodes, new Set(["r1", "e1"])).map((n) => n.id).join(","), "r2");
});

test("routePayload emits node_ids for fixed routes and hops for relay routes", () => {
  assert.deepEqual(routePayload(["r1", "e1"], 17896), {
    node_ids: ["r1", "e1"],
    port: 17896,
  });
  assert.deepEqual(routePayload(["relay:url-test:src-relay", "e1"], "17896"), {
    hops: [
      { relay: { strategy: "url-test", source_id: "src-relay" } },
      { node_id: "e1" },
    ],
    port: 17896,
  });
  assert.deepEqual(
    routePayload(["relay-custom:0", "e1"], 17896, [
      { relay: { strategy: "fallback", node_ids: ["r1", "r2"] } },
      { node_id: "e1" },
    ]),
    {
      hops: [
        { relay: { strategy: "fallback", node_ids: ["r1", "r2"] } },
        { node_id: "e1" },
      ],
      port: 17896,
    },
  );
});
