import { useState } from "react";

export interface LegendEntry {
  label: string;
  color: string;
}

interface LegendProps {
  entries: LegendEntry[];
}

/**
 * Phase C-3: collapsible color legend rendered inside the React Flow canvas.
 * Each entry shows a color swatch and the service category name so users can
 * decode the node border colors without consulting external documentation.
 */
export function Legend({ entries }: LegendProps) {
  const [open, setOpen] = useState(true);

  return (
    <div
      data-testid="graph-legend"
      className="bg-white/90 backdrop-blur-sm border border-gray-200 rounded-lg
                 shadow-sm text-xs select-none"
      style={{ minWidth: 120 }}
    >
      <button
        aria-label={open ? "Hide legend" : "Show legend"}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center justify-between w-full px-2 py-1.5
                   font-semibold text-gray-600 hover:text-gray-900"
      >
        <span>Legend</span>
        <span className="ml-2 text-gray-400">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <ul className="px-2 pb-2 space-y-1">
          {entries.map((e) => (
            <li key={e.label} className="flex items-center gap-1.5">
              <span
                data-testid="legend-swatch"
                className="w-3 h-3 rounded-sm shrink-0"
                style={{ backgroundColor: e.color }}
              />
              <span className="text-gray-700">{e.label}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
