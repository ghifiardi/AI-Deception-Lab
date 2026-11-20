/**
 * Recorded VM1/VM2 results, read from the local dashboard server
 * (cloud/gcp/dashboard-control.mjs, GET /api/lab/results). Opt-in network module:
 * it is only called when the operator asks for recorded runs, so the default
 * simulator stays offline. Same-origin only; read-only.
 */
export interface RecordedRow {
  file: string;
  label: string | null;
  mode: string | null;
  attested: boolean;
  stackId: string | null;
  agents: number;
  startedAt: string;
}

export async function fetchRecordedList(): Promise<RecordedRow[]> {
  const res = await fetch('/api/lab/results', { cache: 'no-store' });
  if (!res.ok) throw new Error(`dashboard server answered HTTP ${res.status}`);
  const body = (await res.json()) as { results?: RecordedRow[] };
  return Array.isArray(body.results) ? body.results : [];
}

export async function fetchRecorded(file: string): Promise<unknown> {
  const res = await fetch(`/api/lab/results/${encodeURIComponent(file)}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
