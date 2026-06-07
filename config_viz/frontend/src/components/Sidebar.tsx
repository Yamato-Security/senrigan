import { useQuery } from "@tanstack/react-query";
import { fetchSnapshots, fetchResourceTypes } from "../api";

interface SidebarProps {
  selectedSnapshotId: string | null;
  onSnapshotSelect: (snapshotId: string) => void;
  onFilterChange: (resourceType: string | undefined) => void;
  searchTerm?: string;
  onSearchChange?: (term: string) => void;
}

/**
 * Left sidebar: snapshot list, resource type filter, and search box.
 */
export function Sidebar({
  selectedSnapshotId,
  onSnapshotSelect,
  onFilterChange,
  searchTerm = "",
  onSearchChange,
}: SidebarProps) {
  const {
    data: snapshots = [],
    isLoading: loadingSnapshots,
  } = useQuery({
    queryKey: ["snapshots"],
    queryFn: fetchSnapshots,
  });

  const { data: resourceTypes = [] } = useQuery({
    queryKey: ["resource-types", selectedSnapshotId],
    queryFn: () => fetchResourceTypes(selectedSnapshotId!),
    enabled: !!selectedSnapshotId,
  });

  return (
    <aside className="w-64 shrink-0 flex flex-col bg-gray-50 border-r border-gray-200 overflow-y-auto">
      {/* Header */}
      <div className="p-4 border-b border-gray-200">
        <h1 className="text-lg font-bold text-gray-800">Config Viz</h1>
        <p className="text-xs text-gray-500 mt-0.5">AWS Resource Graph</p>
      </div>

      {/* Phase B-2: resource search */}
      <div className="p-4 border-b border-gray-200">
        <input
          type="search"
          role="searchbox"
          placeholder="Search resources…"
          value={searchTerm}
          onChange={(e) => onSearchChange?.(e.target.value)}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1 bg-white focus:outline-none focus:border-blue-400"
        />
      </div>

      {/* Resource type filter (BF-07) */}
      {selectedSnapshotId && (
        <div className="p-4 border-b border-gray-200">
          <label
            htmlFor="resource-type-filter"
            className="text-xs font-medium text-gray-600 block mb-1"
          >
            Filter by Type
          </label>
          <select
            id="resource-type-filter"
            className="w-full text-xs border border-gray-300 rounded px-2 py-1 bg-white"
            defaultValue=""
            onChange={(e) => onFilterChange(e.target.value || undefined)}
          >
            <option value="">All types</option>
            {resourceTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Snapshot list (BF-01) */}
      <div className="p-4 flex-1">
        <p className="text-xs font-medium text-gray-600 mb-2">Snapshots</p>
        {loadingSnapshots ? (
          <p className="text-xs text-gray-400">Loading…</p>
        ) : snapshots.length === 0 ? (
          <p className="text-xs text-gray-400">No snapshots found.</p>
        ) : (
          <ul className="space-y-1">
            {snapshots.map((snap) => (
              <li key={snap.snapshot_id}>
                <button
                  onClick={() => onSnapshotSelect(snap.snapshot_id)}
                  className={[
                    "w-full text-left px-2 py-1.5 rounded text-xs",
                    selectedSnapshotId === snap.snapshot_id
                      ? "bg-blue-100 text-blue-800 font-semibold"
                      : "text-gray-700 hover:bg-gray-100",
                  ].join(" ")}
                >
                  <div className="font-medium truncate">{snap.snapshot_id}</div>
                  <div className="text-gray-400 truncate">
                    {snap.aws_region} · {snap.record_count} resources
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  );
}

