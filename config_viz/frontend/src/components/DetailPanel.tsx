import { useQuery } from "@tanstack/react-query";
import { fetchResourceDetail } from "../api";

interface DetailPanelProps {
  snapshotId: string;
  resourceId: string;
  onClose: () => void;
}

/**
 * Slide-in panel showing full configuration and tags for a selected resource.
 * BF-06: fetches GET /api/snapshots/{id}/resources/{rid}.
 */
export function DetailPanel({ snapshotId, resourceId, onClose }: DetailPanelProps) {
  const { data, isLoading } = useQuery({
    queryKey: ["resource-detail", snapshotId, resourceId],
    queryFn: () => fetchResourceDetail(snapshotId, resourceId),
    enabled: !!(snapshotId && resourceId),
  });

  return (
    <aside className="w-80 shrink-0 flex flex-col bg-white border-l border-gray-200 overflow-y-auto shadow-lg">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
        <h2 className="text-sm font-semibold text-gray-800 truncate">
          {isLoading ? "Loading…" : (data?.resource_name ?? data?.resource_id ?? resourceId)}
        </h2>
        <button
          aria-label="Close"
          onClick={onClose}
          className="ml-2 text-gray-400 hover:text-gray-700 text-lg leading-none"
        >
          ×
        </button>
      </div>

      {isLoading ? (
        <div className="p-4 text-xs text-gray-400">Loading…</div>
      ) : !data ? (
        <div className="p-4 text-xs text-red-500">Resource not found.</div>
      ) : (
        <div className="p-4 space-y-4 text-xs">
          {/* Metadata */}
          <section>
            <p className="font-semibold text-gray-600 mb-1">Info</p>
            <dl className="space-y-1">
              <div className="flex gap-2">
                <dt className="text-gray-400 w-24 shrink-0">Type</dt>
                <dd className="text-gray-800 break-all">{data.resource_type}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-gray-400 w-24 shrink-0">Region</dt>
                <dd className="text-gray-800">{data.aws_region}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-gray-400 w-24 shrink-0">ID</dt>
                <dd className="text-gray-800 break-all">{data.resource_id}</dd>
              </div>
            </dl>
          </section>

          {/* Tags */}
          {data.tags && Object.keys(data.tags).length > 0 && (
            <section>
              <p className="font-semibold text-gray-600 mb-1">Tags</p>
              <dl className="space-y-1">
                {Object.entries(data.tags).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <dt className="text-gray-400 w-24 shrink-0 truncate">{k}</dt>
                    <dd className="text-gray-800 break-all">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}

          {/* Configuration */}
          {data.configuration && (
            <section>
              <p className="font-semibold text-gray-600 mb-1">Configuration</p>
              <pre className="bg-gray-50 border border-gray-200 rounded p-2 text-[10px] overflow-auto max-h-96 whitespace-pre-wrap break-all">
                {JSON.stringify(data.configuration, null, 2)}
              </pre>
            </section>
          )}
        </div>
      )}
    </aside>
  );
}

