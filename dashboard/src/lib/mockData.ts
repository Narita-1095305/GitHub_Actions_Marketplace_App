// Mock data for dashboard testing
export const mockDashboardData = {
  organization: {
    id: 1,
    github_org: 'test-org',
    name: 'Test Organization'
  },
  summary: {
    total_repositories: 12,
    total_scans: 45,
    average_risk_score: 6.2,
    total_vulnerabilities: 89,
    high_risk_repos: 3,
    last_scan_time: '2024-01-07T10:30:00Z'
  },
  recent_scans: [
    {
      id: 1,
      overall_risk_score: 8.2,
      total_vulnerabilities: 15,
      created_at: '2024-01-07T10:30:00Z',
      repository: {
        name: 'frontend-app',
        language: 'TypeScript'
      }
    },
    {
      id: 2,
      overall_risk_score: 3.5,
      total_vulnerabilities: 3,
      created_at: '2024-01-07T09:15:00Z',
      repository: {
        name: 'api-server',
        language: 'Go'
      }
    }
  ],
  top_vulnerabilities: [
    {
      id: 1,
      cve_id: 'CVE-2023-1234',
      package_name: 'express',
      package_version: '4.17.1',
      risk_score: 8.2,
      cvss_score: 8.5,
      severity: 'High',
      is_direct: true
    },
    {
      id: 2,
      cve_id: 'CVE-2023-5678',
      package_name: 'lodash',
      package_version: '4.17.20',
      risk_score: 4.8,
      cvss_score: 4.3,
      severity: 'Medium',
      is_direct: false
    }
  ],
  risk_trend: [
    { date: '2024-01-01', risk_score: 6.2, vuln_count: 15 },
    { date: '2024-01-02', risk_score: 5.8, vuln_count: 12 },
    { date: '2024-01-03', risk_score: 7.1, vuln_count: 18 },
    { date: '2024-01-04', risk_score: 6.5, vuln_count: 14 },
    { date: '2024-01-05', risk_score: 5.9, vuln_count: 11 },
    { date: '2024-01-06', risk_score: 6.8, vuln_count: 16 },
    { date: '2024-01-07', risk_score: 6.3, vuln_count: 13 }
  ],
  repository_stats: [
    {
      repository: { id: 1, name: 'frontend-app', language: 'TypeScript' },
      latest_scan: { overall_risk_score: 8.2, total_vulnerabilities: 15 },
      risk_trend: 'increasing' as const,
      last_scan_time: '2024-01-07T10:30:00Z'
    },
    {
      repository: { id: 2, name: 'api-server', language: 'Go' },
      latest_scan: { overall_risk_score: 3.5, total_vulnerabilities: 3 },
      risk_trend: 'decreasing' as const,
      last_scan_time: '2024-01-07T09:15:00Z'
    },
    {
      repository: { id: 3, name: 'data-processor', language: 'Python' },
      latest_scan: { overall_risk_score: 6.8, total_vulnerabilities: 12 },
      risk_trend: 'stable' as const,
      last_scan_time: '2024-01-07T08:45:00Z'
    }
  ]
}