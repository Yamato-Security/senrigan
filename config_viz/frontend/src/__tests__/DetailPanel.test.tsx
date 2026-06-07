import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DetailPanel } from "../components/DetailPanel";

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

// BF-06: DetailPanel calls GET /api/snapshots/{id}/resources/{rid} and shows detail
describe("DetailPanel", () => {
  it("fetches and displays resource detail (BF-06)", async () => {
    render(
      <DetailPanel
        snapshotId="snap-001"
        resourceId="ec2-456"
        onClose={() => {}}
      />,
      { wrapper }
    );

    // Loading state — both h2 and body may say "Loading…"
    expect(screen.getAllByText(/loading/i).length).toBeGreaterThan(0);

    // After data loads, resource name appears in the heading
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "my-instance" })).toBeInTheDocument();
    });
    expect(screen.getByText(/AWS::EC2::Instance/)).toBeInTheDocument();
    expect(screen.getByText(/t3\.micro/)).toBeInTheDocument();
  });

  it("shows close button and calls onClose when clicked", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();

    render(
      <DetailPanel
        snapshotId="snap-001"
        resourceId="ec2-456"
        onClose={onClose}
      />,
      { wrapper }
    );

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "my-instance" })).toBeInTheDocument();
    });
    const closeBtn = screen.getByRole("button", { name: /close/i });
    await user.click(closeBtn);
    expect(onClose).toHaveBeenCalled();
  });

  it("shows tags when present", async () => {
    render(
      <DetailPanel
        snapshotId="snap-001"
        resourceId="ec2-456"
        onClose={() => {}}
      />,
      { wrapper }
    );

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "my-instance" })).toBeInTheDocument();
    });
    expect(screen.getByText(/Name/)).toBeInTheDocument();
    expect(screen.getByText(/prod/)).toBeInTheDocument();
  });
});



