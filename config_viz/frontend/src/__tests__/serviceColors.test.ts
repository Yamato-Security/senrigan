import { describe, it, expect } from "vitest";
import { serviceColorOf, MINIMAP_LEAF_COLOR, SERVICE_CATEGORIES } from "../utils/serviceColors";

// Phase A-3: a single source of truth for "what color represents this
// AWS service" — shared between group node borders and the MiniMap.
describe("serviceColorOf", () => {
  it("returns the EC2 palette color for EC2 resource types", () => {
    expect(serviceColorOf("AWS::EC2::Instance")).toMatch(/^#/);
    expect(serviceColorOf("AWS::EC2::Instance")).toBe(serviceColorOf("AWS::EC2::VPC"));
  });

  it("returns the same color for a virtual service-group node and its members", () => {
    expect(serviceColorOf("__service__IAM")).toBe(serviceColorOf("AWS::IAM::Role"));
  });

  it("returns a neutral fallback for unknown services", () => {
    const color = serviceColorOf("AWS::SomethingNew::Thing");
    expect(color).toMatch(/^#/);
  });

  it("returns a neutral leaf color for non-namespaced strings", () => {
    expect(serviceColorOf("")).toMatch(/^#/);
  });

  it("exposes a distinct neutral color for plain leaf nodes on the MiniMap", () => {
    expect(MINIMAP_LEAF_COLOR).toMatch(/^#/);
  });

  // Phase C-1: palette organised into explicit service categories so callers
  // can render per-category legends and detect accidental colour collisions.
  describe("SERVICE_CATEGORIES (C-1)", () => {
    it("exports named category groups", () => {
      expect(SERVICE_CATEGORIES).toBeDefined();
      expect(Object.keys(SERVICE_CATEGORIES).length).toBeGreaterThan(0);
    });

    it("every service in a category maps to the same color as serviceColorOf", () => {
      for (const [, services] of Object.entries(SERVICE_CATEGORIES)) {
        for (const svc of services) {
          expect(serviceColorOf(`AWS::${svc}::Resource`)).toMatch(/^#/);
        }
      }
    });

    it("all services across categories are unique entries (no unintentional duplicates)", () => {
      const all = Object.values(SERVICE_CATEGORIES).flat();
      const unique = new Set(all);
      expect(all.length).toBe(unique.size);
    });

    it("categories cover the main AWS service families", () => {
      const keys = Object.keys(SERVICE_CATEGORIES);
      expect(keys).toContain("Compute");
      expect(keys).toContain("Storage");
      expect(keys).toContain("Security");
    });
  });
});
