export interface Organization {
  id: number
  github_org: string
  name: string
  created_at: string
  updated_at: string
}

export interface Repository {
  id: number
  org_id: number
  github_repo: string
  name: string
  language: string
  created_at: string
  updated_at: string
}

export interface Scan {
  id: number
  repo_id: number
  commit_sha: string
  branch: string
  overall_risk_score: number
  total_vulnerabilities: number
  high_risk_count: number
  medium_risk_count: number
  low_risk_count: number
  scan_duration: number
  created_at: string
  updated_at: string
  repository?: Repository
}

export interface Vulnerability {
  id: number
  scan_id: number
  cve_id: string
  package_name: string
  package_version: string
  cvss_score: number
  risk_score: number
  severity: string
  is_direct: boolean
  description: string
  created_at: string
  updated_at: string
}

export interface DashboardSummary {
  total_repositories: number
  total_scans: number
  average_risk_score: number
  total_vulnerabilities: number
  high_risk_repos: number
  last_scan_time?: string
}

export interface RiskTrendPoint {
  date: string
  risk_score: number
  vuln_count: number
}

export interface RepositoryStats {
  repository: Repository
  latest_scan?: Scan
  risk_trend: 'increasing' | 'decreasing' | 'stable'
  vulnerability_count: number
  last_scan_time?: string
}

export interface APIResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

export interface PaginatedResponse<T = any> {
  data: T[]
  pagination: {
    page: number
    page_size: number
    total: number
    total_pages: number
  }
}