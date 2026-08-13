export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface Finding {
  rule_id: string
  title: string
  category: string
  severity: Severity
  passed: boolean
  evidence: string
  remediation: string
  mapping: string
  latency_ms: number
}

export interface Scan {
  id: string
  target_name: string
  target_profile: string
  status: string
  score: number
  risk_level: string
  passed: number
  failed: number
  duration_ms: number
  findings: Finding[]
  created_at: string
}

export interface Dashboard {
  total_scans: number
  average_score: number
  high_risk_findings: number
  pass_rate: number
  latest_scan: Scan | null
  category_risk: Record<string, number>
}

export interface Rule {
  id: string
  title: string
  category: string
  severity: Severity
  description: string
  mitigation: string
  atlas_technique?: string
  owasp_mapping: string
}

export interface Capabilities {
  network_targets_enabled: boolean
  allowlisted_hosts: string[]
  supported_profiles: string[]
  report_formats: string[]
}

export interface ScanRequest {
  target_name: string
  target_profile: string
  endpoint_url?: string
  response_field?: string
  bearer_token?: string
}
