import { describe, it, expect } from "vitest";
import { getVisibleNodes, rewireEdges } from "../utils/collapse";
import type { ApiGraphNode, ApiGraphEdge } from "../types";

// Minimal node factory for tests.
function node(id: string, parentId: string | null = null): ApiGraphNode {
  return {
    id,
    type: "awsNode",
    position: { x: 0, y: 0 },
    parentId,
    data: {
      resource_id: id,
      resource_type: "AWS::EC2::Instance",
      resource_name: id,
      aws_region: "us-east-1",
      is_container: false,
    },
  };
}

function edge(id: string, source: string, target: string): ApiGraphEdge {
  return { id, source, target };
}

// Hierarchy: vpc → subnet → ec2; s3 is standalone.
const vpc    = node("vpc", null);
const subnet = node("subnet", "vpc");
const ec2    = node("ec2", "subnet");
const s3     = node("s3", null);
const allNodes = [vpc, subnet, ec2, s3];

// Phase B-3: collapse utilities.
describe("getVisibleNodes", () => {
  it("returns all nodes when nothing is collapsed", () => {
    const result = getVisibleNodes(allNodes, new Set());
    expect(result.map((n) => n.id)).toEqual(expect.arrayContaining(["vpc", "subnet", "ec2", "s3"]));
    expect(result).toHaveLength(4);
  });

  it("hides direct children when their parent is collapsed", () => {
    const result = getVisibleNodes(allNodes, new Set(["vpc"]));
    const ids = result.map((n) => n.id);
    expect(ids).toContain("vpc");
    expect(ids).toContain("s3");
    expect(ids).not.toContain("subnet");
    expect(ids).not.toContain("ec2");
  });

  it("hides grandchildren when an ancestor is collapsed", () => {
    const result = getVisibleNodes(allNodes, new Set(["vpc"]));
    expect(result.map((n) => n.id)).not.toContain("ec2");
  });
});

describe("rewireEdges", () => {
  it("passes through edges between visible nodes unchanged", () => {
    const e = edge("e1", "vpc", "s3");
    const result = rewireEdges([e], new Set(), allNodes);
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe("vpc");
    expect(result[0].target).toBe("s3");
  });

  it("rewires edge source from hidden child to its collapsed ancestor", () => {
    // ec2 is hidden (vpc collapsed); edge ec2→s3 should become vpc→s3.
    const e = edge("e1", "ec2", "s3");
    const result = rewireEdges([e], new Set(["vpc"]), allNodes);
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe("vpc");
    expect(result[0].target).toBe("s3");
  });

  it("rewires edge target from hidden child to its collapsed ancestor", () => {
    const e = edge("e1", "s3", "ec2");
    const result = rewireEdges([e], new Set(["vpc"]), allNodes);
    expect(result).toHaveLength(1);
    expect(result[0].target).toBe("vpc");
  });

  it("drops edges that resolve to a self-loop after rewiring", () => {
    // subnet→ec2: both are inside vpc (collapsed) → both rewire to vpc → self-loop.
    const e = edge("e1", "subnet", "ec2");
    const result = rewireEdges([e], new Set(["vpc"]), allNodes);
    expect(result).toHaveLength(0);
  });

  it("deduplicates edges that rewire to the same pair", () => {
    const edges = [
      edge("e1", "ec2", "s3"),
      edge("e2", "subnet", "s3"),
    ];
    const result = rewireEdges(edges, new Set(["vpc"]), allNodes);
    // Both rewire to vpc→s3 — only one edge should remain.
    expect(result).toHaveLength(1);
  });
});
