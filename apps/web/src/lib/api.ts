/**
 * Thin fetch wrapper. Every security decision is made by the API; this only
 * attaches the CSRF token to state-changing requests and normalises errors.
 */
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public fields: Record<string, string> = {},
    public details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  form?: FormData;
  signal?: AbortSignal;
}

async function toError(res: Response): Promise<ApiError> {
  let payload: { error?: { code?: string; message?: string; details?: Record<string, unknown> } } = {};
  try {
    payload = await res.json();
  } catch {
    /* not JSON */
  }
  const error = payload.error ?? {};
  const details = error.details ?? {};
  const fields = (details.fields as Record<string, string> | undefined) ?? {};
  return new ApiError(res.status, error.code ?? 'error', error.message ?? 'Something went wrong. Please try again.', fields, details);
}

function headers(method: string, json: boolean): HeadersInit {
  const h: Record<string, string> = { Accept: 'application/json' };
  if (json) h['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) h['X-CSRF-Token'] = csrfToken;
  return h;
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? (options.body !== undefined || options.form ? 'POST' : 'GET');
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: headers(method, options.body !== undefined),
    body: options.form ?? (options.body !== undefined ? JSON.stringify(options.body) : undefined),
    signal: options.signal,
  });
  if (!res.ok) throw await toError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Fetch binary content (PDF, image) for in-page viewing. */
export async function apiBlob(path: string): Promise<Blob> {
  const res = await fetch(path, { credentials: 'same-origin' });
  if (!res.ok) throw await toError(res);
  return res.blob();
}

/** POST that answers with a file (the recipient-copy preview). JSON body or multipart form. */
export async function apiPostBlob(path: string, options: { body?: unknown; form?: FormData }): Promise<Blob> {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: headers('POST', options.body !== undefined),
    body: options.form ?? JSON.stringify(options.body ?? {}),
  });
  if (!res.ok) throw await toError(res);
  return res.blob();
}

/** Multipart upload with progress, used for documents. */
export function uploadWithProgress<T>(path: string, form: FormData, onProgress: (fraction: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', path);
    xhr.withCredentials = true;
    xhr.setRequestHeader('Accept', 'application/json');
    if (csrfToken) xhr.setRequestHeader('X-CSRF-Token', csrfToken);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      let body: unknown = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* ignore */
      }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body as T);
      const err = (body as { error?: { code?: string; message?: string; details?: { fields?: Record<string, string> } } } | null)?.error;
      reject(new ApiError(xhr.status, err?.code ?? 'error', err?.message ?? 'Upload failed', err?.details?.fields ?? {}));
    };
    xhr.onerror = () => reject(new ApiError(0, 'network', 'Network error. Check your connection and try again.'));
    xhr.send(form);
  });
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return 'Something went wrong. Please try again.';
}
