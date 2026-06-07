import { createContext, useContext } from "react";

interface CollapseContextValue {
  collapsedIds: Set<string>;
  toggleCollapse: (id: string) => void;
}

const DEFAULT: CollapseContextValue = {
  collapsedIds: new Set(),
  toggleCollapse: () => {},
};

/**
 * Phase B-3: provides the current collapse state to descendant group node
 * components. Wrapped by GraphCanvas so AwsGroupNode can read and update it
 * without prop-drilling through the React Flow node registry.
 */
export const CollapseContext = createContext<CollapseContextValue>(DEFAULT);

export function useCollapse(): CollapseContextValue {
  return useContext(CollapseContext);
}
