import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AwsNode } from "../components/AwsNode";

// Mock reactflow: Handle requires zustand provider context, which is unavailable in isolation
vi.mock("reactflow", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Top: "top", Bottom: "bottom", Left: "left", Right: "right" },
}));

// BF-04: AwsNode shows tooltip on hover (ID / Name / Type)
describe("AwsNode", () => {
  const data = {
    resource_id: "ec2-456",
    resource_type: "AWS::EC2::Instance",
    resource_name: "my-instance",
    aws_region: "us-east-1",
    is_container: false,
  };

  it("renders the resource name", () => {
    render(<AwsNode id="ec2-456" data={data} />);
    expect(screen.getByText("my-instance")).toBeInTheDocument();
  });

  it("falls back to resource_id when resource_name is null", () => {
    render(<AwsNode id="ec2-456" data={{ ...data, resource_name: null }} />);
    expect(screen.getByText("ec2-456")).toBeInTheDocument();
  });

  it("shows tooltip with ID, Name and Type on hover", async () => {
    const user = userEvent.setup();
    render(<AwsNode id="ec2-456" data={data} />);

    const node = screen.getByTestId("aws-node");
    await user.hover(node);

    const tooltip = screen.getByRole("tooltip");
    expect(tooltip).toBeInTheDocument();
    // Verify tooltip contains the key fields
    expect(within(tooltip).getByText("ec2-456")).toBeInTheDocument();
    expect(within(tooltip).getByText("my-instance")).toBeInTheDocument();
    expect(within(tooltip).getByText(/AWS::EC2::Instance/)).toBeInTheDocument();
  });

  it("hides tooltip on mouse leave", async () => {
    const user = userEvent.setup();
    render(<AwsNode id="ec2-456" data={data} />);

    const node = screen.getByTestId("aws-node");
    await user.hover(node);
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    await user.unhover(node);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  // Phase C-2: wider nodes and wrapping tooltips prevent content truncation on
  // resources with long ARN-style IDs.
  describe("label & tooltip width (C-2)", () => {
    it("node container allows up to 260px width", () => {
      render(<AwsNode id="ec2-456" data={data} />);
      const node = screen.getByTestId("aws-node");
      // max-w-[260px] must appear in the className
      expect(node.className).toMatch(/max-w-\[260px\]/);
    });

    it("tooltip does not use whitespace-nowrap (allows line wrapping)", async () => {
      const user = userEvent.setup();
      render(<AwsNode id="ec2-456" data={data} />);
      await user.hover(screen.getByTestId("aws-node"));
      const tooltip = screen.getByRole("tooltip");
      expect(tooltip.className).not.toMatch(/whitespace-nowrap/);
    });

    it("tooltip has a bounded max-width so it does not overflow the viewport", async () => {
      const user = userEvent.setup();
      render(<AwsNode id="ec2-456" data={data} />);
      await user.hover(screen.getByTestId("aws-node"));
      const tooltip = screen.getByRole("tooltip");
      expect(tooltip.className).toMatch(/max-w/);
    });
  });

  it("uses Top/Bottom handles (TB layout)", () => {
    render(<AwsNode id="ec2-456" data={data} />);
    expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
    expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
  });

  // Label truncation: long IDs must not overflow the node box
  describe("label truncation (TR)", () => {
    const LONG_ID = "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdefghij";

    it("TR-A: long resource_id is truncated with ellipsis in the node label", () => {
      render(<AwsNode id={LONG_ID} data={{ ...data, resource_name: null }} />);
      const labelSpan = screen.getByTestId("aws-node").querySelector("span.truncate");
      expect(labelSpan?.textContent?.endsWith("…")).toBe(true);
    });

    it("TR-B: full ID is still shown in the tooltip after truncation", async () => {
      const user = userEvent.setup();
      render(<AwsNode id={LONG_ID} data={{ ...data, resource_name: null }} />);
      await user.hover(screen.getByTestId("aws-node"));
      const tooltip = screen.getByRole("tooltip");
      expect(within(tooltip).getByText(LONG_ID)).toBeInTheDocument();
    });
  });
});
