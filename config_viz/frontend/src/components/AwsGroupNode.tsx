import { Handle, Position } from "reactflow";
import type { NodeData } from "../types";
import { getIconUrl } from "../utils/icons";
import { NEUTRAL_COLOR, serviceColorOf } from "../utils/serviceColors";
import { useCollapse } from "./CollapseContext";
import { truncateLabel } from "../utils/label";

interface AwsGroupNodeProps {
  id: string;
  data: NodeData & { member_count?: number };
  selected?: boolean;
}

// Tinted background and text shades keyed off the category primary color.
// Keys match CATEGORY_COLOR values in serviceColors.ts.
const SERVICE_SECONDARY: Record<string, { bg: string; text: string }> = {
  "#FF9900": { bg: "#FFF8EE", text: "#7A4500" }, // Compute (amber)
  "#3F8624": { bg: "#F0FAF0", text: "#1A4A0A" }, // Storage (green)
  "#527FFF": { bg: "#EDF2FF", text: "#1E3A8A" }, // Database (blue)
  "#8C4FFF": { bg: "#F1ECFF", text: "#3A1E7A" }, // Network (purple)
  "#DD344C": { bg: "#FFF0F2", text: "#7A1020" }, // Security (red)
  "#FF4F8B": { bg: "#FFF0F6", text: "#7A1545" }, // Integration (pink)
  "#E7157B": { bg: "#FDF0F7", text: "#7A0845" }, // Management (magenta)
  "#EE3524": { bg: "#FEF0EE", text: "#7A1510" }, // Developer (coral)
};

const DEFAULT_STYLE = { border: NEUTRAL_COLOR, bg: "#F9FAFB", text: "#374151" };

/**
 * Background tint applied on top of the service-color base per nesting depth.
 * Index 0 = service-group (depth 0), index 1 = VPC (depth 1), etc.
 * Each step adds a subtle dark overlay so deeply nested containers are visually
 * distinct without clashing with the service colour palette.
 */
const DEPTH_BG_TINT = [
  "transparent",        // 0: service-group — base colour only
  "rgba(0,0,0,0.00)",   // 1: VPC
  "rgba(0,0,0,0.04)",   // 2: Subnet
  "rgba(0,0,0,0.08)",   // 3+: inner containers
];

function _getStyle(resourceType: string) {
  const border = serviceColorOf(resourceType);
  if (border === NEUTRAL_COLOR) return DEFAULT_STYLE;
  const secondary = SERVICE_SECONDARY[border];
  return secondary ? { border, ...secondary } : DEFAULT_STYLE;
}

/**
 * Custom React Flow node for container AWS resources (service groups, VPCs, Subnets…).
 * Renders a labeled dashed-border rectangle that can visually contain child nodes.
 * Service-group virtual nodes (id starts with "__svc__") use a bold colored header.
 */
export function AwsGroupNode({ id, data, selected }: AwsGroupNodeProps) {
  const label = truncateLabel(data.resource_name ?? id);
  const isServiceGroup = data.resource_type?.startsWith("__service__");
  const style = _getStyle(data.resource_type ?? "");
  const { collapsedIds, toggleCollapse } = useCollapse();
  const isCollapsed = collapsedIds.has(id);

  // Depth-aware background: apply a subtle tint for deeper nesting levels.
  const depth = (data as typeof data & { depth?: number }).depth ?? 0;
  const depthTint = DEPTH_BG_TINT[Math.min(depth, DEPTH_BG_TINT.length - 1)];

  return (
    <div
      data-testid="aws-group-node"
      data-depth={depth}
      style={{
        borderColor: selected ? "#3B82F6" : style.border,
        backgroundColor: depthTint === "transparent" ? style.bg : style.bg,
        backgroundImage:
          depthTint !== "transparent"
            ? `linear-gradient(${depthTint}, ${depthTint})`
            : undefined,
        width: "100%",
        height: "100%",
        minWidth: isServiceGroup ? 240 : 180,
        minHeight: isServiceGroup ? 140 : 100,
        boxSizing: "border-box",
      }}
      className={[
        "group-node relative rounded-lg border-2 border-dashed",
        "p-2",
        selected ? "ring-2 ring-blue-400" : "",
      ].join(" ")}
    >
      <Handle type="target" position={Position.Top} className="!w-2 !h-2 opacity-50" />

      {/* Header */}
      <div
        className="flex items-center gap-1.5 mb-1 pb-1"
        style={{
          borderBottom: isServiceGroup ? `1px solid ${style.border}40` : "none",
        }}
      >
        <img
          src={getIconUrl(data.resource_type ?? "")}
          alt={data.resource_type ?? ""}
          className="shrink-0"
          style={{ width: isServiceGroup ? 20 : 16, height: isServiceGroup ? 20 : 16 }}
          onError={(e) => {
            (e.currentTarget as HTMLImageElement).src = "/icons/default.png";
          }}
        />
        <span
          className="truncate font-semibold leading-tight"
          style={{
            color: style.text,
            fontSize: isServiceGroup ? "12px" : "10px",
          }}
        >
          {label}
        </span>
        {isServiceGroup && data.member_count !== undefined && (
          <span
            className="ml-auto shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-bold"
            style={{ backgroundColor: `${style.border}20`, color: style.border }}
          >
            {data.member_count}
          </span>
        )}

        {/* Phase B-3: collapse / expand toggle */}
        <button
          aria-label={isCollapsed ? "Expand group" : "Collapse group"}
          onClick={(e) => {
            // Stop the event reaching React Flow's drag/pan handler.
            e.stopPropagation();
            toggleCollapse(id);
          }}
          className="ml-auto shrink-0 w-4 h-4 flex items-center justify-center
                     rounded text-[10px] hover:bg-black/10 transition-colors"
          style={{ color: style.text }}
        >
          {isCollapsed ? "▶" : "▼"}
        </button>
      </div>

      {!isServiceGroup && (
        <div className="text-[9px] truncate" style={{ color: `${style.text}99` }}>
          {data.resource_type}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!w-2 !h-2 opacity-50" />
    </div>
  );
}
