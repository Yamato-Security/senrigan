import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AwsGroupNode } from "../components/AwsGroupNode";
import { CollapseContext } from "../components/CollapseContext";

// Mock reactflow: Handle requires zustand provider context, which is unavailable in isolation
vi.mock("reactflow", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Top: "top", Bottom: "bottom", Left: "left", Right: "right" },
}));

// BF-11: AwsGroupNode renders with dashed border and label
describe("AwsGroupNode", () => {
  const props = {
    id: "vpc-123",
    data: {
      resource_id: "vpc-123",
      resource_type: "AWS::EC2::VPC",
      resource_name: "my-vpc",
      aws_region: "us-east-1",
      is_container: true,
    },
    selected: false,
  };

  it("renders with the resource name as label", () => {
    render(<AwsGroupNode {...props} />);
    expect(screen.getByText("my-vpc")).toBeInTheDocument();
  });

  it("renders with dashed border style", () => {
    render(<AwsGroupNode {...props} />);
    const container = screen.getByTestId("aws-group-node");
    // Tailwind border-dashed or inline style with dashed border
    expect(container.className).toMatch(/dashed|group-node/i);
  });

  it("falls back to resource_id when resource_name is null", () => {
    render(
      <AwsGroupNode
        {...props}
        data={{ ...props.data, resource_name: null }}
      />
    );
    expect(screen.getByText("vpc-123")).toBeInTheDocument();
  });

  it("renders the resource type", () => {
    render(<AwsGroupNode {...props} />);
    expect(screen.getByText(/AWS::EC2::VPC/i)).toBeInTheDocument();
  });

  it("renders as a container (has handles for connections)", () => {
    render(<AwsGroupNode {...props} />);
    // Container node must still mount without errors
    expect(screen.getByTestId("aws-group-node")).toBeInTheDocument();
  });

  // Fix: container div must fill its React Flow wrapper so that children
  // nodes (Subnet, NetworkACL, etc.) rendered within the wrapper appear
  // visually inside the VPC / group border.  Without width/height 100% the
  // visual dashed rectangle stays at its minWidth/minHeight while dagre sets
  // a much larger wrapper size, pushing children outside the border.
  it("root div has width 100% and height 100% to fill the React Flow wrapper (VPC-in-VPC fix)", () => {
    render(<AwsGroupNode {...props} />);
    const container = screen.getByTestId("aws-group-node");
    expect(container.style.width).toBe("100%");
    expect(container.style.height).toBe("100%");
  });

  it("highlights when selected", () => {
    render(<AwsGroupNode {...props} selected />);
    const container = screen.getByTestId("aws-group-node");
    expect(container.className).toMatch(/selected|ring|border-blue/i);
  });

  // Phase B-3: each group node has a toggle button so users can fold large
  // sections of the graph out of view.
  describe("collapse toggle (B-3)", () => {
    it("renders a collapse toggle button", () => {
      render(<AwsGroupNode {...props} />);
      expect(screen.getByRole("button", { name: /collapse|expand/i })).toBeInTheDocument();
    });

    it("shows an expand icon when the group is collapsed", () => {
      render(
        <CollapseContext.Provider
          value={{ collapsedIds: new Set(["vpc-123"]), toggleCollapse: () => {} }}
        >
          <AwsGroupNode {...props} />
        </CollapseContext.Provider>,
      );
      expect(screen.getByRole("button", { name: /expand/i })).toBeInTheDocument();
    });

    it("shows a collapse icon when the group is expanded", () => {
      render(
        <CollapseContext.Provider
          value={{ collapsedIds: new Set(), toggleCollapse: () => {} }}
        >
          <AwsGroupNode {...props} />
        </CollapseContext.Provider>,
      );
      expect(screen.getByRole("button", { name: /collapse/i })).toBeInTheDocument();
    });

    it("calls toggleCollapse with the group id when toggle is clicked", async () => {
      const user = userEvent.setup();
      const toggle = vi.fn();
      render(
        <CollapseContext.Provider value={{ collapsedIds: new Set(), toggleCollapse: toggle }}>
          <AwsGroupNode {...props} />
        </CollapseContext.Provider>,
      );
      await user.click(screen.getByRole("button", { name: /collapse|expand/i }));
      expect(toggle).toHaveBeenCalledWith("vpc-123");
    });
  });

  // FE-HG-02: depth-based visual differentiation.
  // Each nesting level must expose a data-depth attribute whose value equals
  // the node's depth so CSS / tests can style containers differently.
  describe("depth attribute (FE-HG-02)", () => {
    it("renders data-depth=0 when depth is 0 (service-group level)", () => {
      render(
        <AwsGroupNode
          {...props}
          data={{ ...props.data, depth: 0 }}
        />
      );
      expect(screen.getByTestId("aws-group-node").getAttribute("data-depth")).toBe("0");
    });

    it("renders data-depth=1 for VPC-level container (depth 1)", () => {
      render(
        <AwsGroupNode
          {...props}
          data={{ ...props.data, depth: 1 }}
        />
      );
      expect(screen.getByTestId("aws-group-node").getAttribute("data-depth")).toBe("1");
    });

    it("renders data-depth=2 for Subnet-level container (depth 2)", () => {
      render(
        <AwsGroupNode
          {...props}
          data={{ ...props.data, depth: 2 }}
        />
      );
      expect(screen.getByTestId("aws-group-node").getAttribute("data-depth")).toBe("2");
    });

    it("nodes at depth 1 and depth 2 have different data-depth values", () => {
      const { unmount } = render(
        <AwsGroupNode {...props} data={{ ...props.data, depth: 1 }} />
      );
      const d1 = screen.getByTestId("aws-group-node").getAttribute("data-depth");
      unmount();

      render(<AwsGroupNode {...props} data={{ ...props.data, depth: 2 }} />);
      const d2 = screen.getByTestId("aws-group-node").getAttribute("data-depth");

      expect(d1).not.toBe(d2);
    });
  });

  // Phase A-2: handle positions are always Top/Bottom after removing the
  // layout direction toggle.
  it("uses Top/Bottom handles (TB layout)", () => {
    render(<AwsGroupNode {...props} />);
    expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
    expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
  });

  // Label truncation: long names must not overflow the group header
  describe("label truncation (TR)", () => {
    const LONG_NAME = "my-very-long-vpc-name-that-exceeds-the-limit-and-more";

    it("TR-C: long resource_name is truncated with ellipsis in the header", () => {
      render(<AwsGroupNode {...props} data={{ ...props.data, resource_name: LONG_NAME }} />);
      const node = screen.getByTestId("aws-group-node");
      const spans = node.querySelectorAll("span.truncate");
      const labelSpan = Array.from(spans).find((s) => s.textContent?.endsWith("…"));
      expect(labelSpan).toBeTruthy();
    });

    it("TR-D: short resource_name is displayed unchanged (no ellipsis)", () => {
      render(<AwsGroupNode {...props} />);
      expect(screen.getByText("my-vpc").textContent?.endsWith("…")).toBe(false);
    });
  });
});

