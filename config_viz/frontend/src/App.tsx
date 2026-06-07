import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ReactFlowProvider } from "reactflow";
import { fetchGraph } from "./api";
import { Sidebar } from "./components/Sidebar";
import { GraphCanvas } from "./components/GraphCanvas";
import { DetailPanel } from "./components/DetailPanel";

/**
 * Root application component.
 * Manages global state: selected snapshot, resource type filter,
 * and currently selected node for the detail panel.
 */
export default function App() {
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [resourceTypeFilter, setResourceTypeFilter] = useState<string | undefined>(undefined);
  const [selectedResourceId, setSelectedResourceId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(new Set());

  const handleToggleCollapse = (id: string) => {
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Fetch graph data when a snapshot is selected (BF-02)
  const { data: graphData } = useQuery({
    queryKey: ["graph", selectedSnapshotId, resourceTypeFilter],
    queryFn: () => fetchGraph(selectedSnapshotId!, resourceTypeFilter),
    enabled: !!selectedSnapshotId,
  });

  const handleSnapshotSelect = (snapshotId: string) => {
    setSelectedSnapshotId(snapshotId);
    setSelectedResourceId(null);
    setResourceTypeFilter(undefined);
  };

  const handleFilterChange = (resourceType: string | undefined) => {
    setResourceTypeFilter(resourceType);
    setSelectedResourceId(null);
  };

  // BF-05: Clicking a node opens the DetailPanel
  const handleNodeClick = (resourceId: string) => {
    setSelectedResourceId(resourceId);
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-gray-100 font-sans">
      {/* Sidebar: snapshot list + filters */}
      <Sidebar
        selectedSnapshotId={selectedSnapshotId}
        onSnapshotSelect={handleSnapshotSelect}
        onFilterChange={handleFilterChange}
        onSearchChange={setSearchTerm}
        searchTerm={searchTerm}
      />

      {/* Main graph area */}
      <main className="flex-1 relative overflow-hidden">
        {!selectedSnapshotId ? (
          <div className="flex h-full items-center justify-center text-gray-400 text-sm">
            Select a snapshot to explore resources.
          </div>
        ) : !graphData ? (
          <div className="flex h-full items-center justify-center text-gray-400 text-sm">
            Loading graph…
          </div>
        ) : graphData.nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-gray-400 text-sm">
            No components to display.
          </div>
        ) : (
          <ReactFlowProvider>
            <GraphCanvas
              nodes={graphData.nodes}
              edges={graphData.edges}
              rankdir="TB"
              onNodeClick={handleNodeClick}
              searchTerm={searchTerm}
              collapsedIds={collapsedIds}
              onToggleCollapse={handleToggleCollapse}
            />
          </ReactFlowProvider>
        )}
      </main>

      {/* Detail panel (BF-05, BF-06) */}
      {selectedSnapshotId && selectedResourceId && (
        <DetailPanel
          snapshotId={selectedSnapshotId}
          resourceId={selectedResourceId}
          onClose={() => setSelectedResourceId(null)}
        />
      )}
    </div>
  );
}

