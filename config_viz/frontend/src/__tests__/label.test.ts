import { describe, it, expect } from "vitest";
import { truncateLabel, LABEL_MAX_CHARS } from "../utils/label";

describe("truncateLabel", () => {
  it("TR-01: short label (≤ LABEL_MAX_CHARS) is returned unchanged", () => {
    const short = "my-instance";
    expect(truncateLabel(short)).toBe(short);
  });

  it("TR-02: long label (> LABEL_MAX_CHARS) is truncated with ellipsis suffix", () => {
    const long = "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef";
    const result = truncateLabel(long);
    expect(result.endsWith("…")).toBe(true);
    expect(result.length).toBeLessThan(long.length);
  });

  it("TR-03: truncated label total length equals maxChars + 1 (text + ellipsis)", () => {
    const long = "a".repeat(LABEL_MAX_CHARS + 10);
    const result = truncateLabel(long);
    expect(result.length).toBe(LABEL_MAX_CHARS + 1);
  });

  it("TR-04: custom maxChars argument overrides the default", () => {
    const text = "hello-world-foo";
    const result = truncateLabel(text, 5);
    expect(result).toBe("hello…");
    expect(result.length).toBe(6);
  });

  it("TR-05: empty string returns empty string without crash", () => {
    expect(truncateLabel("")).toBe("");
  });

  it("TR-06: label exactly LABEL_MAX_CHARS long is returned unchanged", () => {
    const exact = "a".repeat(LABEL_MAX_CHARS);
    expect(truncateLabel(exact)).toBe(exact);
  });
});
