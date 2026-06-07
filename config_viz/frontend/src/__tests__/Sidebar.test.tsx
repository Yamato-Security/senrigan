import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Sidebar } from "../components/Sidebar";

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

// BF-01: Sidebar fetches snapshot list from GET /api/snapshots and renders it
// BF-07: Changing resource type filter triggers graph API re-fetch  (via onFilterChange)
describe("Sidebar", () => {
  it("fetches and renders snapshot list (BF-01)", async () => {
    render(
      <Sidebar
        selectedSnapshotId={null}
        onSnapshotSelect={() => {}}
        onFilterChange={() => {}}
      />,
      { wrapper }
    );

    // Loading state
    expect(screen.getByText(/loading/i)).toBeInTheDocument();

    // After data loads
    await waitFor(() => {
      expect(screen.getByText("snap-001")).toBeInTheDocument();
    });
    expect(screen.getByText("snap-002")).toBeInTheDocument();
  });

  it("calls onSnapshotSelect when a snapshot is clicked", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();

    render(
      <Sidebar
        selectedSnapshotId={null}
        onSnapshotSelect={onSelect}
        onFilterChange={() => {}}
      />,
      { wrapper }
    );

    await waitFor(() => screen.getByText("snap-001"));
    await user.click(screen.getByText("snap-001"));
    expect(onSelect).toHaveBeenCalledWith("snap-001");
  });

  it("calls onFilterChange when resource type filter changes (BF-07)", async () => {
    const user = userEvent.setup();
    const onFilterChange = vi.fn();

    render(
      <Sidebar
        selectedSnapshotId="snap-001"
        onSnapshotSelect={() => {}}
        onFilterChange={onFilterChange}
      />,
      { wrapper }
    );

    // Wait for resource type options to load (not just the combobox itself)
    await waitFor(() =>
      screen.getByRole("option", { name: "AWS::EC2::Instance" })
    );
    const select = screen.getByRole("combobox");
    await user.selectOptions(select, "AWS::EC2::Instance");
    expect(onFilterChange).toHaveBeenCalledWith("AWS::EC2::Instance");
  });

  // Phase B-2: search input lets users find resources by name or ID without
  // scrolling the entire graph.
  describe("search box (B-2)", () => {
    it("renders a search input", () => {
      render(
        <Sidebar
          selectedSnapshotId={null}
          onSnapshotSelect={() => {}}
          onFilterChange={() => {}}
          onSearchChange={() => {}}
          searchTerm=""
        />,
        { wrapper },
      );
      expect(screen.getByRole("searchbox")).toBeInTheDocument();
    });

    it("calls onSearchChange when the user types in the search box", async () => {
      const user = userEvent.setup();
      const onSearchChange = vi.fn();

      render(
        <Sidebar
          selectedSnapshotId={null}
          onSnapshotSelect={() => {}}
          onFilterChange={() => {}}
          onSearchChange={onSearchChange}
          searchTerm=""
        />,
        { wrapper },
      );

      // Use fireEvent.change to set the full value at once — the input is
      // controlled with a static prop in this test so user.type would reset
      // after each keystroke.
      fireEvent.change(screen.getByRole("searchbox"), { target: { value: "my-vpc" } });
      expect(onSearchChange).toHaveBeenCalledWith("my-vpc");
    });
  });
});
