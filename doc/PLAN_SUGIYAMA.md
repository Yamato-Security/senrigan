# Plan: Hierarchical Layout — Sugiyama Algorithm Migration

## 1. Motivation & Current Limitations

### Current state (`@dagrejs/dagre`)

`config_viz/frontend/src/utils/layout.ts` applies a **two-pass flat-dagre** strategy:

1. **Bottom-up pass** — recursively measures each group's required size by running dagre on its children in isolation.
2. **Top-down pass** — runs dagre again on root-level nodes using the computed sizes.

This workaround exists because calling `g.setParent()` in `@dagrejs/dagre` v1.x crashes
("`Cannot set properties of undefined (setting 'rank')`") whenever an edge crosses the
hierarchy boundary (e.g. VPC → SecurityGroup in different service groups).

### Known problems

| # | Problem | Impact |
|---|---------|--------|
| P-1 | Flat dagre ignores cross-hierarchy edges during layout | Connected groups may end up visually far apart |
| P-2 | Root-level groups use fixed `rankdir: "LR"` ignoring user preference | Disconnected service groups stack horizontally |
| P-3 | No true Sugiyama layer assignment — sibling order is arbitrary | Excessive edge crossings for large snapshots |
| P-4 | Synchronous layout blocks the React render thread | Possible jank on graphs with 200+ nodes |
| P-5 | No cycle removal — circular references in AWS Config data could crash dagre | Silent failures on unusual snapshots |
| P-6 | Node labels (resource IDs) can overflow parent containers | Visual clutter when IDs are long (e.g. ARNs) |

---

## 2. Target Library: `elkjs` v0.11.1

**ELK** (Eclipse Layout Kernel) is a Java layout engine compiled to JavaScript via GWT.

```
elkjs description: "Automatic graph layout based on Sugiyama's algorithm.
Specialized for data flow diagrams and ports."
```

### Why ELK over dagre / d3-dag

| Feature | `@dagrejs/dagre` | `d3-dag` | **`elkjs`** |
|---------|-----------------|---------|------------|
| Compound graph (children[]) | ❌ Crashes | ❌ Not supported | ✅ Native |
| Cross-hierarchy edges | ❌ Manual workaround | ❌ | ✅ Supported |
| True Sugiyama (5 phases) | Partial | ✅ | ✅ Full |
| Cycle removal | Basic | ❌ (DAGs only) | ✅ GREEDY / DEPTH\_FIRST |
| Edge routing styles | Basic | Basic | ✅ ORTHOGONAL / POLYLINE |
| API style | Synchronous | Synchronous | ✅ Async (Promise) |
| ReactFlow examples | Many | Few | ✅ Official `@xyflow` examples |

### ELK `layered` algorithm — the 5 Sugiyama phases

```
Phase 1: Cycle Breaking      → elk.layered.cycleBreaking.strategy = GREEDY
Phase 2: Layer Assignment    → elk.layered.layering.strategy = NETWORK_SIMPLEX
Phase 3: Crossing Minimiza.  → elk.layered.crossingMinimization.strategy = LAYER_SWEEP
Phase 4: Node Placement      → elk.layered.nodePlacement.strategy = BRANDES_KOEPF
Phase 5: Edge Routing        → elk.layered.edgeRouting = ORTHOGONAL
```

---

## 3. Current Implementation State

| Artifact | Status |
|----------|--------|
| `elkjs` in `node_modules` | ✅ Installed |
| `elkjs` in `package.json` | ❌ Not declared — must be added |
| `layout_elk.test.ts` (LT-01…LT-12) | ✅ All 12 tests written |
| `applyElkLayout` in `layout.ts` | ❌ Not yet implemented |
| `GraphCanvas.tsx` migration | ❌ Still uses `applyDagreLayout` |
| ID truncation utility | ❌ Not yet implemented |
| ID truncation tests | ❌ Not yet written |

---

## 4. Architecture Changes

### Files modified

| File | Change |
|------|--------|
| `frontend/package.json` | Declare `elkjs@0.11.1`; remove `@dagrejs/dagre` |
| `frontend/src/utils/layout.ts` | Add `applyElkLayout` (async); keep `applyDagreLayout` until Cycle 8 |
| `frontend/src/utils/label.ts` | New: `truncateLabel(text, maxChars)` utility |
| `frontend/src/components/GraphCanvas.tsx` | Switch to async layout in `useEffect`; add `layoutPending` state |
| `frontend/src/components/AwsNode.tsx` | Apply `truncateLabel` to displayed ID/name |
| `frontend/src/components/AwsGroupNode.tsx` | Apply `truncateLabel` to displayed ID/name |
| `frontend/src/__tests__/layout_elk.test.ts` | Already complete — no changes needed |
| `frontend/src/__tests__/label.test.ts` | New: TDD tests for `truncateLabel` |
| `frontend/src/__tests__/AwsNode.test.tsx` | Add truncation rendering tests |
| `frontend/src/__tests__/AwsGroupNode.test.tsx` | Add truncation rendering tests |

### New public API — layout

```typescript
// layout.ts
export async function applyElkLayout(
  nodes: Node[],
  edges: Edge[],
  direction?: "TB" | "LR",
): Promise<Node[]>;
```

The function is **async** — ELK's layout computation runs in a Promise.
The old `applyDagreLayout` export is **removed** once `GraphCanvas.tsx` is migrated.

### New public API — label truncation

```typescript
// utils/label.ts
export const LABEL_MAX_CHARS = 24;

export function truncateLabel(text: string, maxChars?: number): string;
// e.g. truncateLabel("arn:aws:ec2:us-east-1:123456789012:instance/i-0abc") → "arn:aws:ec2:us-east-1:12…"
```

### ELK node/edge mapping

```typescript
// ReactFlow Node  →  ELK ElkNode
{
  id: node.id,
  width: nodeWidth,
  height: nodeHeight,
  children: childElkNodes[],   // compound support
  layoutOptions: { ... },
}

// ReactFlow Edge → ELK ElkEdge
{
  id: edge.id,
  sources: [edge.source],
  targets: [edge.target],
}
```

### ELK result → ReactFlow positions

ELK returns absolute positions for all nodes in the hierarchy.
Child positions returned by ELK are already **relative to their parent** when using
compound layout — this matches React Flow's `extent: "parent"` requirement.

---

## 5. TDD Test List

### Feature A — ELK layout (already written in `layout_elk.test.ts`)

| ID | Description | Status |
|----|-------------|--------|
| LT-01 | `applyElkLayout` returns a Promise that resolves to a Node array with valid (non-NaN) positions | Written |
| LT-02 | Compound graph — child with `parentNode` receives valid position | Written |
| LT-03 | Solo node (no edges) gets valid position | Written |
| LT-04 | Three-level compound: VPC `style.width/height` is large enough to contain Subnet + ACL | Written |
| LT-05 | Four-level compound: Subnet dimensions > 0 and instances fit inside Subnet | Written |
| LT-06 | **Direction TB**: node B (target of A→B edge) has `position.y > position.y` of A | Written |
| LT-07 | **Direction LR**: node B (target of A→B edge) has `position.x > position.x` of A | Written |
| LT-08 | **Cycle safety**: graph with A→B→A edge (cycle) does not throw; all nodes get positions | Written |
| LT-09 | **Disconnected components**: two separate subgraphs both get valid, non-overlapping positions | Written |
| LT-10 | **Empty graph**: `applyElkLayout([], [])` resolves to `[]` | Written |
| LT-11 | **Cross-hierarchy edge**: edge from child of group-A to child of group-B is accepted without crash | Written |
| LT-12 | **Re-layout stability**: calling `applyElkLayout` twice with identical input produces identical positions | Written |

### Feature B — Label truncation (to be written in `label.test.ts`)

| ID | Description |
|----|-------------|
| TR-01 | Short label (≤ 24 chars) is returned unchanged |
| TR-02 | Long label (> 24 chars) is truncated with `…` suffix |
| TR-03 | Truncated label total length equals `maxChars + 1` (text + ellipsis) |
| TR-04 | Custom `maxChars` argument overrides the default |
| TR-05 | Empty string returns empty string without crash |
| TR-06 | Label exactly 24 chars is returned unchanged |

---

## 6. Implementation Steps (Red-Green-Refactor Cycles)

### Step 0 — Declare package (prerequisite, not TDD)

```bash
cd config_viz/frontend
# elkjs is already installed in node_modules; declare it in package.json
npm install elkjs@0.11.1
```

`@dagrejs/dagre` removal is deferred until Cycle 8 to avoid breaking the existing
`layout.test.ts` suite during the transition.

---

### Cycle 1 — ELK skeleton: LT-01, LT-10

**Red:** `applyElkLayout` does not exist in `layout.ts`. Both LT-01 and LT-10 already fail.

**Green:** Add `applyElkLayout` stub to `layout.ts`:

```typescript
import ELK from "elkjs";
const elk = new ELK();

export async function applyElkLayout(
  nodes: Node[],
  edges: Edge[],
  direction: "TB" | "LR" = "TB",
): Promise<Node[]> {
  if (nodes.length === 0) return [];
  // build ElkNode tree → call elk.layout() → map positions back
}
```

**Refactor:** Extract `toElkNode(node)` / `toElkEdge(edge)` helpers.

---

### Cycle 2 — Direction: LT-06, LT-07

**Red:** LT-06 and LT-07 fail (no direction enforcement).

**Green:** Pass `"elk.algorithm": "layered"` and `"elk.direction": direction === "TB" ? "DOWN" : "RIGHT"` in `layoutOptions`.

**Refactor:** Extract `buildLayoutOptions(direction)`.

---

### Cycle 3 — Compound graph: LT-02, LT-04, LT-05

**Red:** Compound tests fail (no `children[]` support).

**Green:** Build `children[]` recursively from `parentNode` relationships.
- Child positions from ELK are parent-relative → assign directly.
- Set `style.width/height` on group nodes from `ElkNode.{width,height}`.

**Refactor:** Extract `buildElkTree(nodes, edges)` returning the root `ElkNode`.

---

### Cycle 4 — Cross-hierarchy edges: LT-11

**Red:** LT-11 fails (cross-hierarchy edge crashes or is silently dropped).

**Green:** Register cross-hierarchy edges at the **lowest common ancestor** level in the ELK tree.

**Refactor:** Extract `findLCA(sourceId, targetId, parentOf)`.

---

### Cycle 5 — Cycle safety: LT-08

**Red:** LT-08 throws.

**Green:** Add `"elk.layered.cycleBreaking.strategy": "GREEDY"` to layout options.

**Refactor:** Wrap `elk.layout()` in `try/catch` — on error, fall back to original node positions rather than crashing.

---

### Cycle 6 — Disconnected components: LT-09

**Red:** LT-09 — disconnected nodes pile up at origin.

**Green:** Add `"elk.separateConnectedComponents": "true"` to layout options.

**Refactor:** Verify bounding boxes of the two subgraphs do not overlap.

---

### Cycle 7 — Solo node + stability: LT-03, LT-12

**Red:** LT-03 and LT-12 fail.

**Green:** Both are trivially satisfied after Cycles 1–6 (ELK handles solo nodes and is deterministic).

**Refactor:** Clean up; confirm all 12 tests pass.

---

### Cycle 8 — GraphCanvas.tsx integration

**Red:** Update `GraphCanvas.test.tsx` — mock `applyElkLayout` as an async function; the mock of `applyDagreLayout` is removed.

**Green:**
- Remove synchronous `applyDagreLayout` call outside hooks in `GraphCanvas.tsx`.
- Add `const [layoutPending, setLayoutPending] = useState(true)`.
- Move layout into `useEffect`:

```typescript
useEffect(() => {
  setLayoutPending(true);
  applyElkLayout(rfNodes, rfEdges, direction).then((laid) => {
    setNodes(laid);
    setLayoutPending(false);
  });
}, [visibleApiNodes, visibleApiEdges, direction]);
```

- Show a spinner / loading overlay while `layoutPending`.
- Remove `import { applyDagreLayout }` and delete `@dagrejs/dagre` from `package.json`.

**Refactor:** Extract `useElkLayout(nodes, edges, direction)` custom hook.

---

### Cycle 9 — Label truncation utility: TR-01…TR-06

**Red:** Write `label.test.ts` with TR-01…TR-06; `label.ts` does not exist yet.

**Green:** Create `frontend/src/utils/label.ts`:

```typescript
export const LABEL_MAX_CHARS = 24;

export function truncateLabel(text: string, maxChars = LABEL_MAX_CHARS): string {
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + "…";
}
```

**Refactor:** Confirm TR-01…TR-06 all pass. No further changes needed.

---

### Cycle 10 — Apply truncation in node components

**Red:** Add render tests to `AwsNode.test.tsx` and `AwsGroupNode.test.tsx`:
- Passing a 50-char `resource_id` as label renders a string ending in `…`.
- The rendered text is at most `LABEL_MAX_CHARS + 1` characters long.

**Green:**
- In `AwsNode.tsx`: replace `const label = data.resource_name ?? id` with:
  ```typescript
  import { truncateLabel } from "../utils/label";
  const label = truncateLabel(data.resource_name ?? id);
  ```
- In `AwsGroupNode.tsx`: same change for `const label = data.resource_name ?? id`.
- The full ID/name remains visible in the hover tooltip (`AwsNode`) and `title` attribute.

**Refactor:** Confirm no existing snapshot tests break. Adjust if needed.

---

## 7. ELK Configuration Reference

```typescript
const ELK_OPTIONS = {
  "elk.algorithm": "layered",
  "elk.direction": "DOWN",                          // DOWN | RIGHT
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
```

---

## 8. Migration Notes & Breaking Changes

| Item | Details |
|------|---------|
| `applyDagreLayout` removed | All callers (`GraphCanvas.tsx`) must switch to `applyElkLayout` |
| Sync → Async | Cannot call inside `useMemo`; must use `useEffect` + `useState` |
| `@dagrejs/dagre` removed | Delete from `package.json`; update `vitest.config.ts` if mocked |
| Bundle size | `elkjs` minified ≈ 280 KB vs dagre ≈ 100 KB — acceptable for local-only tool |
| Web Worker | ELK can run in a Worker via `elkjs/lib/elk-worker.js`; consider for 500+ node graphs |
| Label truncation | Full ID/name still shown in hover tooltip and `title` attribute; only display text is shortened |

---

## 9. Acceptance Criteria

A migration is **complete** when:

- [ ] `npm test` — all 12 ELK layout tests pass (LT-01 … LT-12)
- [ ] `npm test` — all 6 label truncation tests pass (TR-01 … TR-06)
- [ ] `npm test` — all existing component tests remain green (33 total)
- [ ] `npm run build` — no TypeScript errors
- [ ] Manual: 3-level compound graph renders without overlap
- [ ] Manual: edge A→B is always drawn top-to-bottom (TB) or left-to-right (LR)
- [ ] Manual: re-ingest + reload produces the same graph layout (LT-12 stability)
- [ ] Manual: long resource IDs (e.g. ARNs) display truncated with `…` in nodes
- [ ] Manual: hovering a node with a truncated label shows the full ID in the tooltip
- [ ] `@dagrejs/dagre` is removed from `package.json`

---

## 10. File Diff Summary

```
config_viz/frontend/
├── package.json                  ← elkjs@0.11.1 declared; @dagrejs/dagre removed
├── src/
│   ├── utils/
│   │   ├── layout.ts             ← applyElkLayout (async) added; applyDagreLayout removed
│   │   └── label.ts              ← NEW: truncateLabel + LABEL_MAX_CHARS
│   ├── components/
│   │   ├── GraphCanvas.tsx       ← async layout via useEffect; layoutPending state
│   │   ├── AwsNode.tsx           ← truncateLabel applied to display label
│   │   └── AwsGroupNode.tsx      ← truncateLabel applied to display label
│   └── __tests__/
│       ├── layout_elk.test.ts    ← already complete (LT-01…LT-12)
│       ├── label.test.ts         ← NEW: TR-01…TR-06
│       ├── AwsNode.test.tsx      ← add truncation rendering tests
│       └── AwsGroupNode.test.tsx ← add truncation rendering tests
```
