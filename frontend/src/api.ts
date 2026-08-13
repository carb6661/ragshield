import type { Capabilities, Dashboard, Rule, Scan, ScanRequest } from './types'

const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!response.ok) {
    const detail = await response.text()
    throw new Error(detail || `Request failed: ${response.status}`)
  }
  return response.json() as Promise<T>
}

export const api = {
  dashboard: () => request<Dashboard>('/dashboard'),
  scans: () => request<Scan[]>('/scans'),
  rules: () => request<Rule[]>('/rules'),
  capabilities: () => request<Capabilities>('/capabilities'),
  createScan: (payload: ScanRequest) =>
    request<Scan>('/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  reportUrl: (id: string, format = 'markdown') => `${API_BASE}/scans/${id}/report?format=${format}`,
}
