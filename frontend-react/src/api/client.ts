const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api';

export async function fetchWithRetry<T>(
  endpoint: string,
  options: RequestInit = {},
  retries = 3,
  backoff = 1000
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;

  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return (await response.json()) as T;
    } catch (error) {
      if (i === retries - 1) {
        console.error(`Fetch failed after ${retries} retries: ${url}`, error);
        throw error;
      }
      console.warn(`Fetch attempt ${i + 1} failed. Retrying in ${backoff}ms...`);
      await new Promise((r) => setTimeout(r, backoff));
      backoff *= 2;
    }
  }

  throw new Error('Unreachable');
}

export async function postJson<T>(endpoint: string, body?: unknown): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || `HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

export { API_BASE_URL };
