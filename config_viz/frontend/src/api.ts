import type { GraphData, ResourceDetail, Snapshot } from "./types";

const BASE = "/api";

export async function fetchSnapshots(): Promise<Snapshot[]> {
  const res = await fetch(`${BASE}/snapshots`);
  if (!res.ok) throw new Error(`Failed to fetch snapshots: ${res.status}`);
  return res.json() as Promise<Snapshot[]>;
}

export async function fetchResourceTypes(snapshotId: string): Promise<string[]> {
  const res = await fetch(`${BASE}/snapshots/${snapshotId}/resource-types`);
  if (!res.ok) throw new Error(`Failed to fetch resource types: ${res.status}`);
  return res.json() as Promise<string[]>;
}

export async function fetchGraph(
  snapshotId: string,
  resourceType?: string,
  limit = 5000
): Promise<GraphData> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (resourceType) params.set("resource_type", resourceType);
  const res = await fetch(`${BASE}/snapshots/${snapshotId}/graph?${params}`);
  if (!res.ok) throw new Error(`Failed to fetch graph: ${res.status}`);
  return res.json() as Promise<GraphData>;
}

export async function fetchResourceDetail(
  snapshotId: string,
  resourceId: string
): Promise<ResourceDetail> {
  const res = await fetch(
    `${BASE}/snapshots/${snapshotId}/resources/${encodeURIComponent(resourceId)}`
  );
  if (!res.ok) throw new Error(`Failed to fetch resource detail: ${res.status}`);
  return res.json() as Promise<ResourceDetail>;
}

