import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { GraphCanvas } from "../components/GraphCanvas";
import type { ApiGraphNode, ApiGraphEdge } from "../types";

// Mock applyElkLayout — returns nodes as-is to avoid ELK async work in component tests
vi.mock("../utils/layout", () => ({
  applyElkLayout: async (nodes: unknown[]) => nodes,
}));

// Mock reactflow to avoid canvas / ResizeObserver issues in jsdom
const { mockReactFlow, fitViewSpy, setViewportSpy } = vi.hoisted(() => {
  const fitViewSpy = vi.fn();
  const setViewportSpy = vi.fn();
  const mockReactFlow = vi.fn(
    ({
      nodes = [],
      edges = [],
      children,
      onNodeClick,
      onPaneClick,
    }: {
      nodes: unknown[];
      edges: unknown[];
      children?: React.ReactNode;
      onNodeClick?: (event: unknown, node: unknown) => void;
      onPaneClick?: () => void;
    }) => (
      <div data-testid="react-flow" onClick={() => onPaneClick?.()}>
        {(
          nodes as Array<{
            id: string;
            parentNode?: string;
            style?: { opacity?: number };
            className?: string;
          }>
        ).map((n) => (
          <div
            key={n.id}
            data-testid={`node-${n.id}`}
            data-parent-node={n.parentNode ?? ""}
            data-node-opacity={n.style?.opacity ?? ""}
            data-node-class={n.className ?? ""}
            onClick={(e) => {
              e.stopPropagation();
              onNodeClick?.(e, n);
            }}
          />
        ))}
        {(
          edges as Array<{
            id: string;
            type?: string;
            label?: string;
            animated?: boolean;
            markerEnd?: { type?: string };
            style?: { stroke?: string; strokeWidth?: number; opacity?: number };
          }>
        ).map((e) => (
          <div
            key={e.id}
            data-testid={`edge-${e.id}`}
            data-edge-type={e.type ?? ""}
            data-edge-label={e.label ?? ""}
            data-edge-animated={e.animated ? "yes" : "no"}
            data-marker-end-type={e.markerEnd?.type ?? ""}
            data-stroke={e.style?.stroke ?? ""}
            data-stroke-width={e.style?.strokeWidth ?? ""}
            data-edge-opacity={e.style?.opacity ?? ""}
          />
        ))}
        {children}
      </div>
    ),
  );
  return { mockReactFlow, fitViewSpy, setViewportSpy };
});

vi.mock("reactflow", () => ({
  // reactflow uses default export as well as named exports
  default: (props: unknown) => mockReactFlow(props as Parameters<typeof mockReactFlow>[0]),
  ReactFlow: (props: unknown) => mockReactFlow(props as Parameters<typeof mockReactFlow>[0]),
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Background: (props: { variant?: string; gap?: number; color?: string }) => (
    <div
      data-testid="rf-background"
      data-variant={props.variant ?? ""}
      data-gap={props.gap ?? ""}
      data-color={props.color ?? ""}
    />
  ),
  Controls: () => null,
  MiniMap: (props: { nodeColor?: unknown }) => (
    <div
      data-testid="rf-minimap"
      data-has-node-color={typeof props.nodeColor === "function" ? "yes" : "no"}
    />
  ),
  Handle: () => null,
  Position: { Top: "top", Bottom: "bottom", Left: "left", Right: "right" },
  useNodesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useEdgesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useReactFlow: () => ({
    fitView: fitViewSpy,
    setViewport: setViewportSpy,
    getViewport: vi.fn(() => ({ x: 0, y: 0, zoom: 1 })),
  }),
  MarkerType: { ArrowClosed: "arrowclosed", Arrow: "arrow" },
  BackgroundVariant: { Dots: "dots", Lines: "lines", Cross: "cross" },
  Panel: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="rf-panel">{children}</div>
  ),
}));

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

// BF-03: GraphCanvas renders correct number of nodes and edges
// BF-12: Nodes with parentId are rendered inside their parent container
describe("GraphCanvas", () => {
  beforeEach(() => {
    fitViewSpy.mockClear();
    setViewportSpy.mockClear();
  });

  // Empty-state: no nodes to render → show placeholder message instead of canvas
  describe("empty state", () => {
    it("shows 'No components to display.' when nodes prop is empty", () => {
      render(<GraphCanvas nodes={[]} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.getByText("No components to display.")).toBeInTheDocument();
    });

    it("does not render the ReactFlow canvas when nodes is empty", () => {
      render(<GraphCanvas nodes={[]} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.queryByTestId("react-flow")).not.toBeInTheDocument();
    });
  });

  const nodes: ApiGraphNode[] = [
    {
      id: "vpc-123",
      type: "awsGroupNode",
      position: { x: 0, y: 0 },
      parentId: null,
      data: {
        resource_id: "vpc-123",
        resource_type: "AWS::EC2::VPC",
        resource_name: "my-vpc",
        aws_region: "us-east-1",
        is_container: true,
      },
    },
    {
      id: "ec2-456",
      type: "awsNode",
      position: { x: 0, y: 0 },
      parentId: "vpc-123",
      data: {
        resource_id: "ec2-456",
        resource_type: "AWS::EC2::Instance",
        resource_name: "my-instance",
        aws_region: "us-east-1",
        is_container: false,
      },
    },
  ];

  const edges: ApiGraphEdge[] = [
    { id: "e1", source: "ec2-456", target: "s3-789", label: "uses" },
  ];

  it("renders correct number of nodes", () => {
    render(<GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
      wrapper,
    });
    expect(screen.getByTestId("node-vpc-123")).toBeInTheDocument();
    expect(screen.getByTestId("node-ec2-456")).toBeInTheDocument();
  });

  it("renders correct number of edges", () => {
    render(<GraphCanvas nodes={nodes} edges={edges} rankdir="TB" onNodeClick={() => {}} />, {
      wrapper,
    });
    expect(screen.getByTestId("edge-e1")).toBeInTheDocument();
  });

  it("maps parentId to parentNode for React Flow (BF-12)", () => {
    render(<GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
      wrapper,
    });
    // ec2-456 has parentId="vpc-123" → should be passed as parentNode="vpc-123" to ReactFlow
    const ec2Node = screen.getByTestId("node-ec2-456");
    expect(ec2Node).toHaveAttribute("data-parent-node", "vpc-123");
  });

  it("node without parentId has empty parentNode", () => {
    render(<GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
      wrapper,
    });
    const vpcNode = screen.getByTestId("node-vpc-123");
    expect(vpcNode).toHaveAttribute("data-parent-node", "");
  });

  // Phase A-1: edges use smoothstep routing with arrow markers and a visible
  // stroke so dependency direction is readable at a glance.
  describe("edge styling (A-1)", () => {
    it("renders edges with smoothstep type", () => {
      render(<GraphCanvas nodes={nodes} edges={edges} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.getByTestId("edge-e1")).toHaveAttribute("data-edge-type", "smoothstep");
    });

    it("renders edges with an arrow marker at the target end", () => {
      render(<GraphCanvas nodes={nodes} edges={edges} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.getByTestId("edge-e1")).toHaveAttribute(
        "data-marker-end-type",
        "arrowclosed",
      );
    });

    it("renders edges with a stroke color and width", () => {
      render(<GraphCanvas nodes={nodes} edges={edges} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      const edge = screen.getByTestId("edge-e1");
      expect(edge.getAttribute("data-stroke")).toMatch(/^#/);
      expect(Number(edge.getAttribute("data-stroke-width"))).toBeGreaterThan(1);
    });

    it("preserves the original edge label", () => {
      render(<GraphCanvas nodes={nodes} edges={edges} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.getByTestId("edge-e1")).toHaveAttribute("data-edge-label", "uses");
    });
  });

  // Phase A-3: Background uses dots so it does not visually compete with the
  // group node dashed borders, and the MiniMap colors nodes by service.
  describe("background & minimap (A-3)", () => {
    it("renders the dots background variant", () => {
      render(<GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.getByTestId("rf-background")).toHaveAttribute("data-variant", "dots");
    });

    it("passes a nodeColor function to the MiniMap", () => {
      render(<GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />, {
        wrapper,
      });
      expect(screen.getByTestId("rf-minimap")).toHaveAttribute("data-has-node-color", "yes");
    });
  });

  // Phase B-1: clicking a node dims unconnected edges/nodes and highlights
  // connected ones; clicking the pane restores everything to full opacity.
  describe("selection highlight (B-1)", () => {
    // vpc-123 ←→ ec2-456 (via e1); s3-789 is unrelated
    const threeNodes: ApiGraphNode[] = [
      {
        id: "vpc-123",
        type: "awsGroupNode",
        position: { x: 0, y: 0 },
        parentId: null,
        data: {
          resource_id: "vpc-123",
          resource_type: "AWS::EC2::VPC",
          resource_name: "my-vpc",
          aws_region: "us-east-1",
          is_container: true,
        },
      },
      {
        id: "ec2-456",
        type: "awsNode",
        position: { x: 0, y: 0 },
        parentId: null,
        data: {
          resource_id: "ec2-456",
          resource_type: "AWS::EC2::Instance",
          resource_name: "my-instance",
          aws_region: "us-east-1",
          is_container: false,
        },
      },
      {
        id: "s3-789",
        type: "awsNode",
        position: { x: 0, y: 0 },
        parentId: null,
        data: {
          resource_id: "s3-789",
          resource_type: "AWS::S3::Bucket",
          resource_name: "my-bucket",
          aws_region: "us-east-1",
          is_container: false,
        },
      },
    ];
    const twoEdges: ApiGraphEdge[] = [
      { id: "e1", source: "vpc-123", target: "ec2-456" },
      { id: "e2", source: "s3-789", target: "ec2-456" },
    ];

    async function clickNode(testId: string) {
      const { userEvent } = await import("@testing-library/user-event");
      await userEvent.setup().click(screen.getByTestId(testId));
    }

    it("animates connected edge when a node is clicked", async () => {
      render(
        <GraphCanvas nodes={threeNodes} edges={twoEdges} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      await clickNode("node-vpc-123");
      expect(screen.getByTestId("edge-e1")).toHaveAttribute("data-edge-animated", "yes");
    });

    it("dims unconnected edge when a node is clicked", async () => {
      render(
        <GraphCanvas nodes={threeNodes} edges={twoEdges} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      await clickNode("node-vpc-123");
      const opacity = Number(screen.getByTestId("edge-e2").getAttribute("data-edge-opacity"));
      expect(opacity).toBeGreaterThan(0);
      expect(opacity).toBeLessThan(1);
    });

    it("dims unconnected node when a node is clicked", async () => {
      render(
        <GraphCanvas nodes={threeNodes} edges={twoEdges} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      await clickNode("node-vpc-123");
      const opacity = Number(screen.getByTestId("node-s3-789").getAttribute("data-node-opacity"));
      expect(opacity).toBeGreaterThan(0);
      expect(opacity).toBeLessThan(1);
    });

    it("restores full opacity after pane click", async () => {
      const user = (await import("@testing-library/user-event")).default.setup();
      render(
        <GraphCanvas nodes={threeNodes} edges={twoEdges} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      await user.click(screen.getByTestId("node-vpc-123"));
      // Click the pane (react-flow div itself)
      await user.click(screen.getByTestId("react-flow"));
      expect(screen.getByTestId("edge-e2")).toHaveAttribute("data-edge-opacity", "");
      expect(screen.getByTestId("node-s3-789")).toHaveAttribute("data-node-opacity", "");
    });
  });

  // Phase B-2: matching nodes get a distinct highlight class so they stand out
  // when the user types a search term in the Sidebar.
  describe("search highlight (B-2)", () => {
    it("adds search-match class to nodes whose name matches searchTerm", () => {
      render(
        <GraphCanvas
          nodes={nodes}
          edges={[]}
          rankdir="TB"
          onNodeClick={() => {}}
          searchTerm="my-instance"
        />,
        { wrapper },
      );
      expect(screen.getByTestId("node-ec2-456")).toHaveAttribute(
        "data-node-class",
        expect.stringContaining("search-match"),
      );
    });

    it("does not add search-match class to non-matching nodes", () => {
      render(
        <GraphCanvas
          nodes={nodes}
          edges={[]}
          rankdir="TB"
          onNodeClick={() => {}}
          searchTerm="my-instance"
        />,
        { wrapper },
      );
      expect(screen.getByTestId("node-vpc-123")).not.toHaveAttribute(
        "data-node-class",
        expect.stringContaining("search-match"),
      );
    });

    it("does not highlight any node when searchTerm is empty", () => {
      render(
        <GraphCanvas
          nodes={nodes}
          edges={[]}
          rankdir="TB"
          onNodeClick={() => {}}
          searchTerm=""
        />,
        { wrapper },
      );
      expect(screen.getByTestId("node-ec2-456")).not.toHaveAttribute(
        "data-node-class",
        expect.stringContaining("search-match"),
      );
    });
  });

  // Phase B-3: collapsedIds hides child nodes from the canvas so large groups
  // can be folded away without losing their parent group node.
  describe("group collapse (B-3)", () => {
    const hierarchyNodes: ApiGraphNode[] = [
      {
        id: "vpc-111",
        type: "awsGroupNode",
        position: { x: 0, y: 0 },
        parentId: null,
        data: {
          resource_id: "vpc-111",
          resource_type: "AWS::EC2::VPC",
          resource_name: "my-vpc",
          aws_region: "us-east-1",
          is_container: true,
        },
      },
      {
        id: "ec2-222",
        type: "awsNode",
        position: { x: 0, y: 0 },
        parentId: "vpc-111",
        data: {
          resource_id: "ec2-222",
          resource_type: "AWS::EC2::Instance",
          resource_name: "my-ec2",
          aws_region: "us-east-1",
          is_container: false,
        },
      },
    ];

    it("hides child nodes when parent group is collapsed", () => {
      render(
        <GraphCanvas
          nodes={hierarchyNodes}
          edges={[]}
          rankdir="TB"
          onNodeClick={() => {}}
          collapsedIds={new Set(["vpc-111"])}
          onToggleCollapse={() => {}}
        />,
        { wrapper },
      );
      expect(screen.getByTestId("node-vpc-111")).toBeInTheDocument();
      expect(screen.queryByTestId("node-ec2-222")).not.toBeInTheDocument();
    });

    it("shows child nodes when parent group is not collapsed", () => {
      render(
        <GraphCanvas
          nodes={hierarchyNodes}
          edges={[]}
          rankdir="TB"
          onNodeClick={() => {}}
          collapsedIds={new Set()}
          onToggleCollapse={() => {}}
        />,
        { wrapper },
      );
      expect(screen.getByTestId("node-vpc-111")).toBeInTheDocument();
      expect(screen.getByTestId("node-ec2-222")).toBeInTheDocument();
    });
  });

  // Phase C-3: the GraphCanvas includes a legend panel so users can decode
  // the service colour coding without external documentation.
  describe("legend panel (C-3)", () => {
    it("renders a legend element inside the graph canvas", () => {
      render(
        <GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      expect(screen.getByTestId("graph-legend")).toBeInTheDocument();
    });
  });

  // Phase B-4: setViewport is called (left-aligned) whenever displayed data or
  // layout direction changes so the graph stays positioned after snapshot/filter
  // switches.
  describe("left-aligned viewport on change (B-4)", () => {
    it("calls setViewport when rankdir changes", async () => {
      const { rerender } = render(
        <GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      setViewportSpy.mockClear();
      rerender(<GraphCanvas nodes={nodes} edges={[]} rankdir="LR" onNodeClick={() => {}} />);
      await waitFor(() => expect(setViewportSpy).toHaveBeenCalled());
    });

    it("calls setViewport when apiNodes change", async () => {
      const { rerender } = render(
        <GraphCanvas nodes={nodes} edges={[]} rankdir="TB" onNodeClick={() => {}} />,
        { wrapper },
      );
      setViewportSpy.mockClear();
      rerender(<GraphCanvas nodes={[nodes[0]]} edges={[]} rankdir="TB" onNodeClick={() => {}} />);
      await waitFor(() => expect(setViewportSpy).toHaveBeenCalled());
    });
  });
});


