import type { Dashboard, Rule, Scan } from './types'

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
  createScan: (targetName: string, targetProfile: string) =>
    request<Scan>('/scans', {
      method: 'POST',
      body: JSON.stringify({ target_name: targetName, target_profile: targetProfile }),
    }),
  reportUrl: (id: string) => `${API_BASE}/scans/${id}/report`,
}

