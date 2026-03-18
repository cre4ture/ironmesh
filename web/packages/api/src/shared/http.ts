export async function fetchJson<T>(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<T> {
  const response = await fetch(input, init);
  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(
      `HTTP ${response.status}: ${JSON.stringify(payload ?? { message: "no JSON body returned" })}`
    );
  }

  return payload as T;
}
