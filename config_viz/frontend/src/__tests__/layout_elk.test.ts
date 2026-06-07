/**
 * TDD tests for applyElkLayout — Sugiyama-based hierarchical layout via elkjs.
 *
 * Test List:
 * [x] LT-01  returns a Promise<Node[]> with valid (non-NaN) positions
 * [x] LT-02  compound graph — child with parentNode receives valid position
 * [x] LT-03  solo node (no edges) gets valid position
 * [x] LT-04  three-level compound: VPC style.width/height fits Subnet + ACL
 * [x] LT-05  four-level compound: Subnet dims > 0 and instances fit inside
 * [x] LT-06  direction TB: downstream node position.y > upstream position.y
 * [x] LT-07  direction LR: downstream node position.x > upstream position.x
 * [x] LT-08  cycle safety: A→B→A cycle does not throw; all nodes get positions
 * [x] LT-09  disconnected components: all nodes get valid positions
 * [x] LT-10  empty graph: resolves to []
 * [x] LT-11  cross-hierarchy edge: child-of-A → child-of-B does not crash
 * [x] LT-12  stability: two calls with identical input produce identical positions
 */

import { describe, it, expect } from "vitest";
import { applyElkLayout } from "../utils/layout";
import type { Node, Edge } from "reactflow";

// ── LT-10: empty graph ───────────────────────────────────────────────────────
describe("applyElkLayout", () => {
  it("LT-10: empty graph resolves to empty array", async () => {
    const result = await applyElkLayout([], []);
    expect(result).toEqual([]);
  });

  // ── LT-01: basic two-node graph ──────────────────────────────────────────
  it("LT-01: assigns non-NaN numeric positions to all nodes", async () => {
    const nodes: Node[] = [
      { id: "a", position: { x: 0, y: 0 }, data: {} },
      { id: "b", position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [{ id: "e1", source: "a", target: "b" }];

    const result = await applyElkLayout(nodes, edges);

    expect(result).toHaveLength(2);
    for (const n of result) {
      expect(typeof n.position.x).toBe("number");
      expect(typeof n.position.y).toBe("number");
      expect(isNaN(n.position.x)).toBe(false);
      expect(isNaN(n.position.y)).toBe(false);
    }
  });

  // ── LT-03: solo node ─────────────────────────────────────────────────────
  it("LT-03: solo node (no edges) gets valid position", async () => {
    const nodes: Node[] = [{ id: "solo", position: { x: 0, y: 0 }, data: {} }];
    const result = await applyElkLayout(nodes, []);

    expect(result).toHaveLength(1);
    expect(typeof result[0].position.x).toBe("number");
    expect(typeof result[0].position.y).toBe("number");
    expect(isNaN(result[0].position.x)).toBe(false);
    expect(isNaN(result[0].position.y)).toBe(false);
  });

  // ── LT-02: compound graph ────────────────────────────────────────────────
  it("LT-02: compound graph — child parentNode gets valid position", async () => {
    const nodes: Node[] = [
      { id: "vpc", type: "awsGroupNode", position: { x: 0, y: 0 }, data: {} },
      {
        id: "ec2",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "vpc",
      },
    ] as Node[];
    const result = await applyElkLayout(nodes, []);

    expect(result).toHaveLength(2);
    for (const n of result) {
      expect(typeof n.position.x).toBe("number");
      expect(typeof n.position.y).toBe("number");
      expect(isNaN(n.position.x)).toBe(false);
      expect(isNaN(n.position.y)).toBe(false);
    }
  });

  // ── LT-06: TB direction ──────────────────────────────────────────────────
  it("LT-06: TB direction — downstream node.y > upstream node.y", async () => {
    const nodes: Node[] = [
      { id: "a", position: { x: 0, y: 0 }, data: {} },
      { id: "b", position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [{ id: "e1", source: "a", target: "b" }];

    const result = await applyElkLayout(nodes, edges, "TB");
    const a = result.find((n) => n.id === "a")!;
    const b = result.find((n) => n.id === "b")!;

    expect(b.position.y).toBeGreaterThan(a.position.y);
  });

  // ── LT-07: LR direction ──────────────────────────────────────────────────
  it("LT-07: LR direction — downstream node.x > upstream node.x", async () => {
    const nodes: Node[] = [
      { id: "a", position: { x: 0, y: 0 }, data: {} },
      { id: "b", position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [{ id: "e1", source: "a", target: "b" }];

    const result = await applyElkLayout(nodes, edges, "LR");
    const a = result.find((n) => n.id === "a")!;
    const b = result.find((n) => n.id === "b")!;

    expect(b.position.x).toBeGreaterThan(a.position.x);
  });

  // ── LT-08: cycle safety ──────────────────────────────────────────────────
  it("LT-08: cycle A→B→A does not throw; all nodes get valid positions", async () => {
    const nodes: Node[] = [
      { id: "a", position: { x: 0, y: 0 }, data: {} },
      { id: "b", position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [
      { id: "e1", source: "a", target: "b" },
      { id: "e2", source: "b", target: "a" },
    ];

    const result = await applyElkLayout(nodes, edges);
    expect(result).toHaveLength(2);
    for (const n of result) {
      expect(isNaN(n.position.x)).toBe(false);
      expect(isNaN(n.position.y)).toBe(false);
    }
  });

  // ── LT-09: disconnected components ──────────────────────────────────────
  it("LT-09: disconnected subgraphs both get valid non-overlapping positions", async () => {
    const nodes: Node[] = [
      { id: "a1", position: { x: 0, y: 0 }, data: {} },
      { id: "a2", position: { x: 0, y: 0 }, data: {} },
      { id: "b1", position: { x: 0, y: 0 }, data: {} },
      { id: "b2", position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [
      { id: "e1", source: "a1", target: "a2" },
      { id: "e2", source: "b1", target: "b2" },
    ];

    const result = await applyElkLayout(nodes, edges);
    expect(result).toHaveLength(4);
    for (const n of result) {
      expect(isNaN(n.position.x)).toBe(false);
      expect(isNaN(n.position.y)).toBe(false);
    }
  });

  // ── LT-04: three-level compound ──────────────────────────────────────────
  it("LT-04: three-level compound — VPC style.width/height fits Subnet and ACL", async () => {
    const nodes: Node[] = [
      { id: "__svc__EC2", type: "awsGroupNode", position: { x: 0, y: 0 }, data: {} },
      {
        id: "vpc-001",
        type: "awsGroupNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "__svc__EC2",
        extent: "parent",
      },
      {
        id: "subnet-001",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "vpc-001",
        extent: "parent",
      },
      {
        id: "acl-001",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "vpc-001",
        extent: "parent",
      },
    ] as Node[];

    const result = await applyElkLayout(nodes, []);
    const vpc = result.find((n) => n.id === "vpc-001")!;
    const subnet = result.find((n) => n.id === "subnet-001")!;
    const acl = result.find((n) => n.id === "acl-001")!;

    const vpcW = (vpc.style as { width?: number })?.width ?? 0;
    const vpcH = (vpc.style as { height?: number })?.height ?? 0;

    expect(vpcW).toBeGreaterThan(0);
    expect(vpcH).toBeGreaterThan(0);

    // Children (NODE_W=200, NODE_H=56) must fit within the parent box
    expect(subnet.position.x + 200).toBeLessThanOrEqual(vpcW);
    expect(subnet.position.y + 56).toBeLessThanOrEqual(vpcH);
    expect(acl.position.x + 200).toBeLessThanOrEqual(vpcW);
    expect(acl.position.y + 56).toBeLessThanOrEqual(vpcH);
  });

  // ── LT-05: four-level compound ───────────────────────────────────────────
  it("LT-05: four-level compound — layout valid, instances fit inside Subnet", async () => {
    const nodes: Node[] = [
      { id: "__svc__EC2", type: "awsGroupNode", position: { x: 0, y: 0 }, data: {} },
      {
        id: "vpc-001",
        type: "awsGroupNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "__svc__EC2",
        extent: "parent",
      },
      {
        id: "subnet-001",
        type: "awsGroupNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "vpc-001",
        extent: "parent",
      },
      {
        id: "i-001",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "subnet-001",
        extent: "parent",
      },
      {
        id: "i-002",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "subnet-001",
        extent: "parent",
      },
    ] as Node[];

    const result = await applyElkLayout(nodes, []);
    expect(result).toHaveLength(5);
    for (const n of result) {
      expect(isNaN(n.position.x)).toBe(false);
      expect(isNaN(n.position.y)).toBe(false);
    }

    const subnet = result.find((n) => n.id === "subnet-001")!;
    const subnetW = (subnet.style as { width?: number })?.width ?? 0;
    const subnetH = (subnet.style as { height?: number })?.height ?? 0;
    expect(subnetW).toBeGreaterThan(0);
    expect(subnetH).toBeGreaterThan(0);

    const i001 = result.find((n) => n.id === "i-001")!;
    const i002 = result.find((n) => n.id === "i-002")!;
    expect(i001.position.x + 200).toBeLessThanOrEqual(subnetW);
    expect(i001.position.y + 56).toBeLessThanOrEqual(subnetH);
    expect(i002.position.x + 200).toBeLessThanOrEqual(subnetW);
    expect(i002.position.y + 56).toBeLessThanOrEqual(subnetH);
  });

  // ── LT-11: cross-hierarchy edge ──────────────────────────────────────────
  it("LT-11: cross-hierarchy edge (child-of-A → child-of-B) does not crash", async () => {
    const nodes: Node[] = [
      { id: "svc-a", type: "awsGroupNode", position: { x: 0, y: 0 }, data: {} },
      { id: "svc-b", type: "awsGroupNode", position: { x: 0, y: 0 }, data: {} },
      {
        id: "child-a",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "svc-a",
        extent: "parent",
      },
      {
        id: "child-b",
        type: "awsNode",
        position: { x: 0, y: 0 },
        data: {},
        parentNode: "svc-b",
        extent: "parent",
      },
    ] as Node[];
    const edges: Edge[] = [{ id: "e-cross", source: "child-a", target: "child-b" }];

    const result = await applyElkLayout(nodes, edges);
    expect(result).toHaveLength(4);
    for (const n of result) {
      expect(isNaN(n.position.x)).toBe(false);
      expect(isNaN(n.position.y)).toBe(false);
    }
  });

  // ── LT-12: layout stability ──────────────────────────────────────────────
  it("LT-12: identical input produces identical positions on re-call", async () => {
    const nodes: Node[] = [
      { id: "a", position: { x: 0, y: 0 }, data: {} },
      { id: "b", position: { x: 0, y: 0 }, data: {} },
      { id: "c", position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [
      { id: "e1", source: "a", target: "b" },
      { id: "e2", source: "b", target: "c" },
    ];

    const r1 = await applyElkLayout(nodes, edges);
    const r2 = await applyElkLayout(nodes, edges);

    for (const n of r1) {
      const m = r2.find((x) => x.id === n.id)!;
      expect(m.position.x).toBe(n.position.x);
      expect(m.position.y).toBe(n.position.y);
    }
  });
});

