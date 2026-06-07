import ELK from "elkjs/lib/elk.bundled.js";
import type { ElkNode, ElkExtendedEdge, LayoutOptions } from "elkjs";
import type { Node, Edge } from "reactflow";

const NODE_W = 200;
const NODE_H = 56;
const GROUP_MIN_W = 240;
const GROUP_MIN_H = 96;

const ROOT_OPTIONS: LayoutOptions = {
  "elk.algorithm": "layered",
  "elk.layered.cycleBreaking.strategy": "GREEDY",
  "elk.layered.layering.strategy": "NETWORK_SIMPLEX",
  "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
  "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
  "elk.layered.edgeRouting": "ORTHOGONAL",
  "elk.separateConnectedComponents": "true",
  "elk.spacing.nodeNode": "56",
  "elk.layered.spacing.nodeNodeBetweenLayers": "80",
  "elk.padding": "[top=32,left=32,bottom=32,right=32]",
};

const CHILD_OPTIONS: LayoutOptions = {
  "elk.algorithm": "layered",
  "elk.layered.cycleBreaking.strategy": "GREEDY",
  "elk.padding": "[top=32,left=32,bottom=32,right=32]",
  "elk.spacing.nodeNode": "40",
  "elk.layered.spacing.nodeNodeBetweenLayers": "60",
};

const elk = new ELK();

function buildMaps(nodes: Node[]): {
  parentOf: Map<string, string>;
  childrenOf: Map<string, string[]>;
} {
  const parentOf = new Map<string, string>();
  const childrenOf = new Map<string, string[]>();
  for (const n of nodes) {
    const p = (n as Node & { parentNode?: string }).parentNode;
    if (p) {
      parentOf.set(n.id, p);
      if (!childrenOf.has(p)) childrenOf.set(p, []);
      childrenOf.get(p)!.push(n.id);
    }
  }
  return { parentOf, childrenOf };
}

// Collect all ancestors of a node (not including itself)
function ancestors(id: string, parentOf: Map<string, string>): Set<string> {
  const result = new Set<string>();
  let cur = parentOf.get(id);
  while (cur) {
    result.add(cur);
    cur = parentOf.get(cur);
  }
  return result;
}

// Returns the id of the container node that should own this edge,
// or null if the edge belongs at the root level.
function findEdgeOwner(
  aId: string,
  bId: string,
  parentOf: Map<string, string>,
): string | null {
  const aParent = parentOf.get(aId) ?? null;
  const bParent = parentOf.get(bId) ?? null;

  // Siblings inside the same container
  if (aParent !== null && aParent === bParent) return aParent;

  const aAnc = ancestors(aId, parentOf);
  const bAnc = ancestors(bId, parentOf);

  // b is a strict ancestor of a → place edge in b's parent
  if (aAnc.has(bId)) return bParent;

  // a is a strict ancestor of b → place edge in a's parent
  if (bAnc.has(aId)) return aParent;

  // Walk up from b's ancestors and find first shared with a's ancestors
  let cur = bParent;
  while (cur !== null && cur !== undefined) {
    if (aAnc.has(cur)) return parentOf.get(cur) ?? null;
    cur = parentOf.get(cur) ?? null;
  }

  return null;
}

function toElkNode(
  id: string,
  nodeById: Map<string, Node>,
  childrenOf: Map<string, string[]>,
  elkDir: string,
): ElkNode {
  const node = nodeById.get(id)!;
  const isGroup = node.type === "awsGroupNode";
  const childIds = childrenOf.get(id) ?? [];

  const elkNode: ElkNode = {
    id,
    width: isGroup ? GROUP_MIN_W : NODE_W,
    height: isGroup ? GROUP_MIN_H : NODE_H,
  };

  if (childIds.length > 0) {
    elkNode.children = childIds.map((cid) =>
      toElkNode(cid, nodeById, childrenOf, elkDir),
    );
    elkNode.layoutOptions = { ...CHILD_OPTIONS, "elk.direction": elkDir };
  }

  return elkNode;
}

function toElkEdge(edge: Edge): ElkExtendedEdge {
  return { id: edge.id, sources: [edge.source], targets: [edge.target] };
}

function injectEdges(
  elkNode: ElkNode,
  byOwner: Map<string | null, ElkExtendedEdge[]>,
): void {
  const owned = byOwner.get(elkNode.id);
  if (owned?.length) elkNode.edges = [...(elkNode.edges ?? []), ...owned];
  for (const child of elkNode.children ?? []) injectEdges(child, byOwner);
}

function extractPositions(
  elkNode: ElkNode,
  out: Map<string, { x: number; y: number; w: number; h: number }>,
  skipRoot: boolean,
): void {
  if (!skipRoot) {
    out.set(elkNode.id, {
      x: elkNode.x ?? 0,
      y: elkNode.y ?? 0,
      w: elkNode.width ?? NODE_W,
      h: elkNode.height ?? NODE_H,
    });
  }
  for (const child of elkNode.children ?? [])
    extractPositions(child, out, false);
}

export async function applyElkLayout(
  nodes: Node[],
  edges: Edge[],
  direction: "TB" | "LR" = "TB",
): Promise<Node[]> {
  if (nodes.length === 0) return [];

  const { parentOf, childrenOf } = buildMaps(nodes);
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const elkDir = direction === "TB" ? "DOWN" : "RIGHT";

  const rootIds = nodes.filter((n) => !parentOf.has(n.id)).map((n) => n.id);
  const elkChildren = rootIds.map((id) =>
    toElkNode(id, nodeById, childrenOf, elkDir),
  );

  // Assign each edge to its owner container
  const byOwner = new Map<string | null, ElkExtendedEdge[]>();
  for (const edge of edges) {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) continue;
    const owner = findEdgeOwner(edge.source, edge.target, parentOf);
    if (!byOwner.has(owner)) byOwner.set(owner, []);
    byOwner.get(owner)!.push(toElkEdge(edge));
  }

  const elkGraph: ElkNode = {
    id: "__root__",
    layoutOptions: { ...ROOT_OPTIONS, "elk.direction": elkDir },
    children: elkChildren,
    edges: byOwner.get(null) ?? [],
  };

  for (const child of elkGraph.children ?? []) injectEdges(child, byOwner);

  try {
    const result = await elk.layout(elkGraph);
    const positions = new Map<
      string,
      { x: number; y: number; w: number; h: number }
    >();
    extractPositions(result, positions, true);

    return nodes.map((node) => {
      const pos = positions.get(node.id);
      if (!pos) return node;
      const isGroup = node.type === "awsGroupNode";
      return {
        ...node,
        position: { x: pos.x, y: pos.y },
        ...(isGroup
          ? {
              style: {
                ...((node.style as object) ?? {}),
                width: pos.w,
                height: pos.h,
              },
            }
          : {}),
      };
    });
  } catch {
    return nodes;
  }
}
