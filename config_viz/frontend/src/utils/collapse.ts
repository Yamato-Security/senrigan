import type { ApiGraphNode, ApiGraphEdge } from "../types";

/**
 * Build a set of node IDs that are hidden because one of their ancestors is
 * in `collapsedIds`. The collapsed group itself remains visible.
 */
function buildHiddenIds(nodes: ApiGraphNode[], collapsedIds: Set<string>): Set<string> {
  const parentOf = new Map(nodes.map((n) => [n.id, n.parentId ?? undefined]));
  const hidden = new Set<string>();

  function isHidden(id: string): boolean {
    const parent = parentOf.get(id);
    if (!parent) return false;
    if (collapsedIds.has(parent)) return true;
    return isHidden(parent);
  }

  for (const n of nodes) {
    if (isHidden(n.id)) hidden.add(n.id);
  }
  return hidden;
}

/**
 * Walk up the parent chain until we reach a node that is not hidden.
 * Returns the node's own ID if it is already visible, or the closest visible
 * ancestor if it is hidden. Returns `null` only when the root itself is hidden
 * (which cannot happen under normal collapse semantics).
 */
function findVisibleAncestor(
  id: string,
  hiddenIds: Set<string>,
  parentOf: Map<string, string | undefined>,
): string | null {
  if (!hiddenIds.has(id)) return id;
  const parent = parentOf.get(id);
  if (!parent) return null;
  return findVisibleAncestor(parent, hiddenIds, parentOf);
}

/** Returns only the nodes that should be rendered given the current collapse state. */
export function getVisibleNodes(
  nodes: ApiGraphNode[],
  collapsedIds: Set<string>,
): ApiGraphNode[] {
  const hidden = buildHiddenIds(nodes, collapsedIds);
  return nodes.filter((n) => !hidden.has(n.id));
}

/**
 * Return edges whose endpoints are both visible after collapsing, rewiring
 * hidden endpoints to their closest visible ancestor. Duplicate edges and
 * self-loops produced by rewiring are dropped.
 */
export function rewireEdges(
  edges: ApiGraphEdge[],
  collapsedIds: Set<string>,
  nodes: ApiGraphNode[],
): ApiGraphEdge[] {
  const parentOf = new Map(nodes.map((n) => [n.id, n.parentId ?? undefined]));
  const hidden = buildHiddenIds(nodes, collapsedIds);

  const seen = new Set<string>();
  const result: ApiGraphEdge[] = [];

  for (const e of edges) {
    const src = findVisibleAncestor(e.source, hidden, parentOf);
    const tgt = findVisibleAncestor(e.target, hidden, parentOf);
    if (!src || !tgt || src === tgt) continue;

    const key = `${src}→${tgt}`;
    if (seen.has(key)) continue;
    seen.add(key);

    result.push({ ...e, source: src, target: tgt });
  }

  return result;
}
