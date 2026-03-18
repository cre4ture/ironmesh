export function readBaseUrl(): string {
  if (typeof window === "undefined") {
    return "";
  }

  return window.location.origin;
}
