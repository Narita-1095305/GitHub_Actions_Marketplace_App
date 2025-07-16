// Enhanced API types with strict type safety

export interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

export interface PaginationMeta {
  page: number
  page_size: number
  total: number
  total_pages: number
}

export interface PaginatedResponse<T> {
  data: T[]
  pagination: PaginationMeta
}

// Strict vulnerability severity enum
export type VulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'

// Risk trend with strict typing
export type RiskTrend = 'increasing' | 'decreasing' | 'stable'

// Enhanced vulnerability interface
export interface Vulnerability {
  readonly id: number
  readonly cve_id: string
  readonly package_name: string
  readonly package_version: string
  readonly risk_score: number
  readonly cvss_score: number | null
  readonly severity: VulnerabilitySeverity
  readonly is_direct: boolean
  readonly description?: string
  readonly fixed_version?: string
  readonly published_date?: string
}

// Enhanced repository interface
export interface Repository {
  readonly id: number
  readonly name: string
  readonly language: string
  readonly github_repo?: string
  readonly created_at: string
  readonly updated_at?: string
}

// Enhanced scan interface
export interface Scan {
  readonly id: number
  readonly overall_risk_score: number
  readonly total_vulnerabilities: number
  readonly created_at: string
  readonly repository: Repository
  readonly status?: 'completed' | 'running' | 'failed'
}

// Type guards for runtime type checking
export function isValidSeverity(severity: string): severity is VulnerabilitySeverity {
  return ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(severity)
}

export function isValidRiskTrend(trend: string): trend is RiskTrend {
  return ['increasing', 'decreasing', 'stable'].includes(trend)
}

// API error types
export class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
    public code?: string
  ) {
    super(message)
    this.name = 'ApiError'
  }
}