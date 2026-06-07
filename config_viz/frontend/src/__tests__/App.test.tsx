import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "../App";

// Mock reactflow for App integration tests
vi.mock("reactflow", () => ({
  default: ({ nodes = [], onNodeClick }: {
    nodes?: Array<{ id: string; data: { resource_id: string } }>;
    onNodeClick?: (event: unknown, node: { id: string; data: { resource_id: string } }) => void;
  }) => (
    <div data-testid="react-flow">
      {nodes.map((n) => (
        <div
          key={n.id}
          data-testid={`node-${n.id}`}
          onClick={(e) => onNodeClick?.(e, n)}
        />
      ))}
    </div>
  ),
  ReactFlow: ({ nodes = [], edges = [], onNodeClick }: {
    nodes?: Array<{ id: string; data: { resource_id: string } }>;
    edges?: unknown[];
    onNodeClick?: (event: unknown, node: { id: string; data: { resource_id: string } }) => void;
  }) => (
    <div data-testid="react-flow">
      {nodes.map((n) => (
        <div
          key={n.id}
          data-testid={`node-${n.id}`}
          onClick={(e) => onNodeClick?.(e, n)}
        />
      ))}
    </div>
  ),
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  Handle: () => null,
  Position: { Top: "top", Bottom: "bottom", Left: "left", Right: "right" },
  useNodesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useEdgesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useReactFlow: () => ({
    fitView: vi.fn(),
    setViewport: vi.fn(),
    getViewport: vi.fn(() => ({ x: 0, y: 0, zoom: 1 })),
  }),
  MarkerType: { ArrowClosed: "arrowclosed", Arrow: "arrow" },
  BackgroundVariant: { Dots: "dots", Lines: "lines", Cross: "cross" },
  Panel: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  Wrapper.displayName = "TestQueryWrapper";
  return Wrapper;
}

// BF-02: Selecting a snapshot triggers graph API call
// BF-05: Clicking AwsNode opens DetailPanel
describe("App", () => {
  it("shows 'No components to display.' when graph has no nodes", async () => {
    const { server } = await import("../mocks/server");
    const { http, HttpResponse } = await import("msw");
    server.use(
      http.get("/api/snapshots/:id/graph", () =>
        HttpResponse.json({ nodes: [], edges: [] }),
      ),
    );

    const user = userEvent.setup();
    render(<App />, { wrapper: makeWrapper() });

    await waitFor(() => screen.getByText("snap-001"));
    await user.click(screen.getByText("snap-001"));

    await waitFor(() => {
      expect(screen.getByText("No components to display.")).toBeInTheDocument();
    });
    expect(screen.queryByTestId("react-flow")).not.toBeInTheDocument();
  });

  it("renders snapshot list and graph on snapshot selection (BF-02)", async () => {
    const user = userEvent.setup();
    render(<App />, { wrapper: makeWrapper() });

    // Wait for snapshot list
    await waitFor(() => screen.getByText("snap-001"));

    // Click on a snapshot
    await user.click(screen.getByText("snap-001"));

    // Graph should appear after snapshot is selected
    await waitFor(() => {
      expect(screen.getByTestId("react-flow")).toBeInTheDocument();
    });
  });

  it("closes the 'No components to display.' message when graph has nodes (BF-02)", async () => {
    const user = userEvent.setup();
    render(<App />, { wrapper: makeWrapper() });

    await waitFor(() => screen.getByText("snap-001"));
    await user.click(screen.getByText("snap-001"));

    await waitFor(() => {
      expect(screen.getByTestId("react-flow")).toBeInTheDocument();
    });
    expect(screen.queryByText("No components to display.")).not.toBeInTheDocument();
  });

  it("opens DetailPanel when a node is clicked (BF-05)", async () => {
    const user = userEvent.setup();
    render(<App />, { wrapper: makeWrapper() });

    // Select snapshot and wait for graph
    await waitFor(() => screen.getByText("snap-001"));
    await user.click(screen.getByText("snap-001"));

    await waitFor(() => screen.getByTestId("node-vpc-123"));

    // Click on a node
    await user.click(screen.getByTestId("node-ec2-456"));

    // DetailPanel should open — heading "my-instance" appears
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "my-instance" })).toBeInTheDocument();
    });
  });
});



