export class HttpError extends Error {
  readonly status: number;
  readonly payload: unknown;

  constructor(status: number, payload: unknown) {
    super(
      `HTTP ${status}: ${JSON.stringify(payload ?? { message: "no JSON body returned" })}`
    );
    this.name = "HttpError";
    this.status = status;
    this.payload = payload;
  }
}

export function isHttpErrorStatus(
  error: unknown,
  ...statuses: number[]
): boolean {
  return error instanceof HttpError && statuses.includes(error.status);
}

export async function fetchJson<T>(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<T> {
  const response = await fetch(input, init);
  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    throw new HttpError(response.status, payload);
  }

  return payload as T;
}
