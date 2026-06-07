import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Legend } from "../components/Legend";

// Phase C-3: the Legend component lets users understand which colour
// corresponds to which AWS service category without leaving the graph.
describe("Legend", () => {
  const services = [
    { label: "Compute", color: "#FF9900" },
    { label: "Security", color: "#DD344C" },
  ];

  it("renders a color swatch for each provided service entry", () => {
    render(<Legend entries={services} />);
    expect(screen.getByText("Compute")).toBeInTheDocument();
    expect(screen.getByText("Security")).toBeInTheDocument();
  });

  it("renders a swatch element with the correct background color", () => {
    render(<Legend entries={services} />);
    const swatches = document.querySelectorAll("[data-testid='legend-swatch']");
    expect(swatches.length).toBe(2);
    expect((swatches[0] as HTMLElement).style.backgroundColor).toBeTruthy();
  });

  it("is visible by default", () => {
    render(<Legend entries={services} />);
    expect(screen.getByRole("list")).toBeInTheDocument();
  });

  it("collapses the list when the toggle button is clicked", async () => {
    const user = userEvent.setup();
    render(<Legend entries={services} />);
    const toggle = screen.getByRole("button", { name: /legend|hide|show/i });
    await user.click(toggle);
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
  });

  it("re-opens when the toggle is clicked again", async () => {
    const user = userEvent.setup();
    render(<Legend entries={services} />);
    const toggle = screen.getByRole("button", { name: /legend|hide|show/i });
    await user.click(toggle);
    await user.click(toggle);
    expect(screen.getByRole("list")).toBeInTheDocument();
  });
});
