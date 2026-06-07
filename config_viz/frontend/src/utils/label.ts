export const LABEL_MAX_CHARS = 24;

export function truncateLabel(text: string, maxChars = LABEL_MAX_CHARS): string {
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + "…";
}
