import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  Panel,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
  type NodeMouseHandler,
} from "reactflow";
import "reactflow/dist/style.css";

import { MINIMAP_LEAF_COLOR, SERVICE_CATEGORIES, NEUTRAL_COLOR, serviceColorOf } from "../utils/serviceColors";
import { getVisibleNodes, rewireEdges } from "../utils/collapse";
import { CollapseContext } from "./CollapseContext";
import { Legend, type LegendEntry } from "./Legend";
import { applyElkLayout } from "../utils/layout";
import { AwsNode } from "./AwsNode";
import { AwsGroupNode } from "./AwsGroupNode";
import type { ApiGraphNode, ApiGraphEdge } from "../types";

const EDGE_STROKE = "#9CA3AF";
const EDGE_STROKE_WIDTH = 1.5;

function _minimapNodeColor(node: Node): string {
  if (node.type === "awsGroupNode") {
    const rt = (node.data as { resource_type?: string } | undefined)?.resource_type ?? "";
    return serviceColorOf(rt);
  }
  return MINIMAP_LEAF_COLOR;
}

const nodeTypes = {
  awsNode: AwsNode,
  awsGroupNode: AwsGroupNode,
};

const LEFT_MARGIN = 24;
const NODE_W_DEFAULT = 200;
const NODE_H_DEFAULT = 56;

function ViewportController({
  laidNodes,
  containerRef,
  rankdir,
}: {
  laidNodes: Node[];
  containerRef: React.RefObject<HTMLDivElement>;
  rankdir: "TB" | "LR";
}) {
  const { setViewport } = useReactFlow();

  useEffect(() => {
    const rootNodes = laidNodes.filter(
      (n) => !(n as Node & { parentNode?: string }).parentNode,
    );
    if (rootNodes.length === 0) return;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of rootNodes) {
      const w = (n.style as { width?: number })?.width ?? NODE_W_DEFAULT;
      const h = (n.style as { height?: number })?.height ?? NODE_H_DEFAULT;
      minX = Math.min(minX, n.position.x);
      minY = Math.min(minY, n.position.y);
      maxX = Math.max(maxX, n.position.x + w);
      maxY = Math.max(maxY, n.position.y + h);
    }

    const graphW = Math.max(maxX - minX, 1);
    const graphH = Math.max(maxY - minY, 1);
    const cW = containerRef.current?.offsetWidth ?? 1200;
    const cH = containerRef.current?.offsetHeight ?? 800;

    const zoom = Math.max(
      0.1,
      Math.min(
        (cW - 2 * LEFT_MARGIN) / graphW,
        (cH - 2 * LEFT_MARGIN) / graphH,
      ),
    );

    setViewport(
      { x: LEFT_MARGIN - minX * zoom, y: LEFT_MARGIN - minY * zoom, zoom },
      { duration: 300 },
    );
  }, [laidNodes, setViewport, containerRef, rankdir]);

  return null;
}

interface GraphCanvasProps {
  nodes: ApiGraphNode[];
  edges: ApiGraphEdge[];
  rankdir: "TB" | "LR";
  onNodeClick: (resourceId: string) => void;
  searchTerm?: string;
  collapsedIds?: Set<string>;
  onToggleCollapse?: (id: string) => void;
}

function topoSort(nodes: Node[]): Node[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const visited = new Set<string>();
  const result: Node[] = [];

  function visit(id: string) {
    if (visited.has(id)) return;
    visited.add(id);
    const node = byId.get(id);
    if (!node) return;
    const pn = (node as Node & { parentNode?: string }).parentNode;
    if (pn) visit(pn);
    result.push(node);
  }

  for (const node of nodes) visit(node.id);
  return result;
}

export function GraphCanvas({
  nodes: apiNodes,
  edges: apiEdges,
  rankdir,
  onNodeClick,
  searchTerm = "",
  collapsedIds = new Set<string>(),
  onToggleCollapse = () => {},
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  const toRfNodes = useCallback(
    (src: ApiGraphNode[]): Node[] => {
      const mapped = src.map((n) => ({
        id: n.id,
        type: n.type,
        position: n.position,
        parentNode: n.parentId ?? undefined,
        extent: n.parentId ? ("parent" as const) : undefined,
        data: n.data,
      }));
      return topoSort(mapped);
    },
    [],
  );

  const toRfEdges = useCallback(
    (src: ApiGraphEdge[]): Edge[] =>
      src.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: false,
        type: "smoothstep",
        style: { stroke: EDGE_STROKE, strokeWidth: EDGE_STROKE_WIDTH },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 14,
          height: 14,
          color: EDGE_STROKE,
        },
        labelStyle: { fill: "#4B5563", fontSize: 10 },
        labelBgStyle: { fill: "#FFFFFF", fillOpacity: 0.85 },
        labelBgPadding: [4, 2],
        labelBgBorderRadius: 2,
      })),
    [],
  );

  const visibleApiNodes = useMemo(
    () => getVisibleNodes(apiNodes, collapsedIds),
    [apiNodes, collapsedIds],
  );
  const visibleApiEdges = useMemo(
    () => rewireEdges(apiEdges, collapsedIds, apiNodes),
    [apiEdges, collapsedIds, apiNodes],
  );

  if (apiNodes.length === 0) {
    return (
      <div className="w-full h-full flex items-center justify-center text-gray-400 text-sm" data-testid="graph-canvas">
        No components to display.
      </div>
    );
  }

  const rfNodes = toRfNodes(visibleApiNodes);
  const rfEdges = toRfEdges(visibleApiEdges);

  const [nodes, setNodes, onNodesChange] = useNodesState(rfNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfEdges);

  // Re-layout whenever visible data or direction changes.
  useEffect(() => {
    const n = toRfNodes(visibleApiNodes);
    const e = toRfEdges(visibleApiEdges);
    applyElkLayout(n, e, rankdir).then((laid) => {
      setNodes(laid);
      setEdges(e);
    });
  }, [visibleApiNodes, visibleApiEdges, rankdir, toRfNodes, toRfEdges, setNodes, setEdges]);

  const [highlightedId, setHighlightedId] = useState<string | null>(null);

  const displayNodes = useMemo(() => {
    const term = searchTerm.toLowerCase();
    const connected = highlightedId ? new Set<string>([highlightedId]) : null;
    if (connected) {
      for (const e of edges) {
        if (e.source === highlightedId) connected.add(e.target);
        if (e.target === highlightedId) connected.add(e.source);
      }
    }

    return nodes.map((n) => {
      let updated: typeof n = n;
      if (connected && !connected.has(n.id)) {
        updated = { ...updated, style: { ...((updated.style as object) ?? {}), opacity: 0.25 } };
      }
      if (term) {
        const d = n.data as { resource_id?: string; resource_name?: string | null };
        const matches =
          d.resource_id?.toLowerCase().includes(term) ||
          d.resource_name?.toLowerCase().includes(term);
        if (matches) {
          updated = {
            ...updated,
            className: ((updated.className ?? "") + " search-match").trim(),
          };
        }
      }
      return updated;
    });
  }, [nodes, edges, highlightedId, searchTerm]);

  const displayEdges = useMemo(() => {
    if (!highlightedId) return edges;
    return edges.map((e) =>
      e.source === highlightedId || e.target === highlightedId
        ? { ...e, animated: true, style: { ...e.style, stroke: "#3B82F6", strokeWidth: 2 } }
        : { ...e, style: { ...e.style, opacity: 0.2 } },
    );
  }, [edges, highlightedId]);

  const handleNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      setHighlightedId(node.id);
      const resourceId = (node.data as { resource_id: string }).resource_id;
      if (!resourceId.startsWith("__svc__")) {
        onNodeClick(resourceId);
      }
    },
    [onNodeClick],
  );

  const handlePaneClick = useCallback(() => {
    setHighlightedId(null);
  }, []);

  const legendEntries = useMemo((): LegendEntry[] => {
    const seen = new Set<string>();
    const result: LegendEntry[] = [];
    for (const n of visibleApiNodes) {
      const color = serviceColorOf(n.data.resource_type ?? "");
      if (color === NEUTRAL_COLOR) continue;
      if (seen.has(color)) continue;
      seen.add(color);
      const category =
        Object.entries(SERVICE_CATEGORIES).find(([, svcs]) =>
          svcs.some((s) => serviceColorOf(`AWS::${s}::X`) === color),
        )?.[0] ?? "Other";
      result.push({ label: category, color });
    }
    return result.sort((a, b) => a.label.localeCompare(b.label));
  }, [visibleApiNodes]);

  return (
    <CollapseContext.Provider value={{ collapsedIds, toggleCollapse: onToggleCollapse }}>
      <div ref={containerRef} className="w-full h-full" data-testid="graph-canvas">
        <ReactFlow
          nodes={displayNodes}
          edges={displayEdges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          onPaneClick={handlePaneClick}
          attributionPosition="bottom-right"
        >
          <ViewportController laidNodes={nodes} containerRef={containerRef} rankdir={rankdir} />
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#E5E7EB" />
          <Controls />
          <Panel position="bottom-left">
            <Legend entries={legendEntries} />
          </Panel>
          <MiniMap
            nodeStrokeWidth={3}
            nodeColor={_minimapNodeColor}
            maskColor="rgba(31,41,55,0.6)"
            pannable
            zoomable
          />
        </ReactFlow>
      </div>
    </CollapseContext.Provider>
  );
}
