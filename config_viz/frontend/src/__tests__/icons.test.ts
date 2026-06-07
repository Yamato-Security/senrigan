import { describe, it, expect } from "vitest";
import { getIconUrl, FALLBACK_ICON } from "../utils/icons";

// BF-09: icons.ts resolves icon URLs with service-level SVG fallback
describe("getIconUrl", () => {
  it("returns a file path for well-known resource types", () => {
    expect(getIconUrl("AWS::EC2::Instance")).toBe("/icons/EC2_Instance.png");
    expect(getIconUrl("AWS::S3::Bucket")).toBe("/icons/S3_Bucket.png");
    expect(getIconUrl("AWS::KMS::Key")).toBe("/icons/KMS_Key.png");
  });

  it("returns an SVG data URI (not FALLBACK_ICON) for unlisted but valid resource types", () => {
    // Any AWS::ServiceNS::ResourceType gets a service-colored SVG badge
    const url = getIconUrl("AWS::Unknown::Type");
    expect(url).not.toBe(FALLBACK_ICON);
    expect(url).toMatch(/^data:image\/svg\+xml;base64,/);
  });

  it("returns an SVG data URI for service-group virtual nodes", () => {
    const url = getIconUrl("__service__EC2");
    expect(url).not.toBe(FALLBACK_ICON);
    expect(url).toMatch(/^data:image\/svg\+xml;base64,/);
  });

  it("returns FALLBACK_ICON for strings with no :: separator", () => {
    expect(getIconUrl("")).toBe(FALLBACK_ICON);
    expect(getIconUrl("not-aws")).toBe(FALLBACK_ICON);
  });

  it("SVG data URI is a non-empty string for any AWS type", () => {
    const types = ["AWS::Foo::Bar", "AWS::Custom::Resource"];
    for (const t of types) {
      const url = getIconUrl(t);
      expect(typeof url).toBe("string");
      expect(url.length).toBeGreaterThan(0);
    }
  });
});
