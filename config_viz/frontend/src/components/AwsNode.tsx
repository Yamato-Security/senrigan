import { useState } from "react";
import { Handle, Position } from "reactflow";
import type { NodeData } from "../types";
import { getIconUrl } from "../utils/icons";
import { truncateLabel } from "../utils/label";

interface AwsNodeProps {
  id: string;
  data: NodeData;
  selected?: boolean;
}

/**
 * Custom React Flow node for leaf AWS resources.
 * Displays resource name/type and shows a tooltip with full details on hover.
 */
export function AwsNode({ id, data, selected }: AwsNodeProps) {
  const [showTooltip, setShowTooltip] = useState(false);

  const fullLabel = data.resource_name ?? id;
  const label = truncateLabel(fullLabel);

  return (
    <div
      data-testid="aws-node"
      className={[
        "relative flex items-center gap-2 px-3 py-2 rounded-md border bg-white shadow-sm",
        "min-w-[160px] max-w-[260px] cursor-pointer select-none text-xs",
        selected
          ? "border-blue-500 ring-2 ring-blue-300"
          : "border-gray-300 hover:border-blue-400",
      ].join(" ")}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <Handle type="target" position={Position.Top} className="!w-2 !h-2" />

      {/* Icon */}
      <img
        src={getIconUrl(data.resource_type)}
        alt={data.resource_type}
        className="w-6 h-6 shrink-0"
        onError={(e) => {
          (e.currentTarget as HTMLImageElement).src = "/icons/default.png";
        }}
      />

      {/* Label */}
      <span className="truncate font-medium text-gray-800">{label}</span>

      <Handle type="source" position={Position.Bottom} className="!w-2 !h-2" />

      {/* Tooltip */}
      {showTooltip && (
        <div
          role="tooltip"
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50
                     bg-gray-900 text-white text-xs rounded px-2 py-1 shadow-lg
                     max-w-[260px] break-words pointer-events-none"
        >
          <div className="font-semibold">{id}</div>
          <div>{data.resource_name ?? "—"}</div>
          <div className="text-gray-300">{data.resource_type}</div>
          <div className="text-gray-400">{data.aws_region}</div>
        </div>
      )}
    </div>
  );
}

