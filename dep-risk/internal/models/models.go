package models

import (
	"time"
)

// Organization represents a GitHub organization
type Organization struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	GitHubOrg string    `json:"github_org" gorm:"uniqueIndex;not null"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Repositories []Repository `json:"repositories,omitempty" gorm:"foreignKey:OrgID"`
}

// Repository represents a GitHub repository
type Repository struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	OrgID      uint      `json:"org_id" gorm:"not null"`
	GitHubRepo string    `json:"github_repo" gorm:"not null"`
	Name       string    `json:"name"`
	Language   string    `json:"language"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Relationships
	Organization *Organization `json:"organization,omitempty" gorm:"foreignKey:OrgID"`
	Scans        []Scan        `json:"scans,omitempty" gorm:"foreignKey:RepoID"`
}

// Scan represents a vulnerability scan result
type Scan struct {
	ID                   uint      `json:"id" gorm:"primaryKey"`
	RepoID               uint      `json:"repo_id" gorm:"not null"`
	CommitSHA            string    `json:"commit_sha" gorm:"size:40"`
	Branch               string    `json:"branch"`
	OverallRiskScore     float64   `json:"overall_risk_score" gorm:"type:decimal(3,1)"`
	TotalVulnerabilities int       `json:"total_vulnerabilities"`
	HighRiskCount        int       `json:"high_risk_count"`
	MediumRiskCount      int       `json:"medium_risk_count"`
	LowRiskCount         int       `json:"low_risk_count"`
	ScanDuration         int       `json:"scan_duration"` // seconds
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`

	// Relationships
	Repository      *Repository     `json:"repository,omitempty" gorm:"foreignKey:RepoID"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" gorm:"foreignKey:ScanID"`
}

// Vulnerability represents a specific vulnerability found in a scan
type Vulnerability struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	ScanID         uint      `json:"scan_id" gorm:"not null"`
	CVEID          string    `json:"cve_id" gorm:"size:50"`
	PackageName    string    `json:"package_name"`
	PackageVersion string    `json:"package_version" gorm:"size:100"`
	CVSSScore      float64   `json:"cvss_score" gorm:"type:decimal(3,1)"`
	RiskScore      float64   `json:"risk_score" gorm:"type:decimal(3,1)"`
	Severity       string    `json:"severity" gorm:"size:20"`
	IsDirect       bool      `json:"is_direct"`
	Description    string    `json:"description" gorm:"type:text"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	// Relationships
	Scan *Scan `json:"scan,omitempty" gorm:"foreignKey:ScanID"`
}

// DashboardData represents aggregated data for the dashboard
type DashboardData struct {
	Organization     *Organization          `json:"organization"`
	Summary          *DashboardSummary      `json:"summary"`
	RecentScans      []Scan                 `json:"recent_scans"`
	TopVulnerabilities []Vulnerability      `json:"top_vulnerabilities"`
	RiskTrend        []RiskTrendPoint       `json:"risk_trend"`
	RepositoryStats  []RepositoryStats      `json:"repository_stats"`
}

// DashboardSummary represents high-level statistics
type DashboardSummary struct {
	TotalRepositories    int     `json:"total_repositories"`
	TotalScans          int     `json:"total_scans"`
	AverageRiskScore    float64 `json:"average_risk_score"`
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	HighRiskRepos       int     `json:"high_risk_repos"`
	LastScanTime        *time.Time `json:"last_scan_time"`
}

// RiskTrendPoint represents a point in the risk trend over time
type RiskTrendPoint struct {
	Date      time.Time `json:"date"`
	RiskScore float64   `json:"risk_score"`
	VulnCount int       `json:"vuln_count"`
}

// RepositoryStats represents statistics for a single repository
type RepositoryStats struct {
	Repository       *Repository `json:"repository"`
	LatestScan       *Scan       `json:"latest_scan"`
	RiskTrend        string      `json:"risk_trend"` // "increasing", "decreasing", "stable"
	VulnerabilityCount int       `json:"vulnerability_count"`
	LastScanTime     *time.Time  `json:"last_scan_time"`
}

// ScanRequest represents the request payload for submitting scan results
type ScanRequest struct {
	Organization    string                    `json:"organization" binding:"required"`
	Repository      string                    `json:"repository" binding:"required"`
	CommitSHA       string                    `json:"commit_sha" binding:"required"`
	Branch          string                    `json:"branch"`
	ScanResult      *ScanResultPayload        `json:"scan_result" binding:"required"`
	Vulnerabilities []VulnerabilityPayload    `json:"vulnerabilities"`
}

// ScanResultPayload represents the scan result data in the request
type ScanResultPayload struct {
	OverallRiskScore     float64 `json:"overall_risk_score" binding:"required"`
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	HighRiskCount        int     `json:"high_risk_count"`
	MediumRiskCount      int     `json:"medium_risk_count"`
	LowRiskCount         int     `json:"low_risk_count"`
	ScanDuration         int     `json:"scan_duration"`
}

// VulnerabilityPayload represents vulnerability data in the request
type VulnerabilityPayload struct {
	CVEID          string  `json:"cve_id" binding:"required"`
	PackageName    string  `json:"package_name" binding:"required"`
	PackageVersion string  `json:"package_version" binding:"required"`
	CVSSScore      float64 `json:"cvss_score"`
	RiskScore      float64 `json:"risk_score" binding:"required"`
	Severity       string  `json:"severity"`
	IsDirect       bool    `json:"is_direct"`
	Description    string  `json:"description"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Page     int `form:"page,default=1" binding:"min=1"`
	PageSize int `form:"page_size,default=20" binding:"min=1,max=100"`
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination *Pagination `json:"pagination"`
}

// Pagination represents pagination metadata
type Pagination struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}