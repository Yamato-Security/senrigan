/** Snapshot metadata returned from GET /api/snapshots */
export interface Snapshot {
  snapshot_id: string;
  account_id: string;
  aws_region: string;
  captured_at: string;
  source_path: string;
  record_count: number;
}

/** Data attached to every graph node (from /api/snapshots/{id}/graph) */
export interface NodeData {
  resource_id: string;
  resource_type: string;
  resource_name: string | null;
  aws_region: string;
  is_container: boolean;
  /** Number of direct members — present only on service-group virtual nodes */
  member_count?: number;
  /**
   * Nesting depth in the containment hierarchy.
   * 0 = service-group / top-level root; increments by 1 for each parent layer.
   * Used by AwsGroupNode to apply depth-aware visual styling.
   */
  depth?: number;
}

/** A single node in the graph response */
export interface ApiGraphNode {
  id: string;
  type: "awsNode" | "awsGroupNode";
  position: { x: number; y: number };
  /** Set when this resource is logically inside a parent container */
  parentId: string | null;
  data: NodeData;
}

/** A single edge in the graph response */
export interface ApiGraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

/** Full graph response from /api/snapshots/{id}/graph */
export interface GraphData {
  nodes: ApiGraphNode[];
  edges: ApiGraphEdge[];
}

/** Full resource detail from /api/snapshots/{id}/resources/{rid} */
export interface ResourceDetail {
  resource_id: string;
  snapshot_id: string;
  resource_type: string;
  aws_region: string;
  resource_name: string | null;
  configuration: Record<string, unknown> | null;
  tags: Record<string, unknown> | null;
}


