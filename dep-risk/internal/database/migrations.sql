-- Dep-Risk Database Schema
-- This file contains the complete database schema for reference
-- GORM will handle the actual migrations automatically

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    github_org VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Repositories table
CREATE TABLE IF NOT EXISTS repositories (
    id SERIAL PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_repo VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    language VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, github_repo)
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha VARCHAR(40),
    branch VARCHAR(255),
    overall_risk_score DECIMAL(3,1),
    total_vulnerabilities INTEGER DEFAULT 0,
    high_risk_count INTEGER DEFAULT 0,
    medium_risk_count INTEGER DEFAULT 0,
    low_risk_count INTEGER DEFAULT 0,
    scan_duration INTEGER DEFAULT 0, -- seconds
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id VARCHAR(50),
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    cvss_score DECIMAL(3,1),
    risk_score DECIMAL(3,1),
    severity VARCHAR(20),
    is_direct BOOLEAN DEFAULT FALSE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_organizations_github_org ON organizations(github_org);
CREATE INDEX IF NOT EXISTS idx_repositories_org_id ON repositories(org_id);
CREATE INDEX IF NOT EXISTS idx_repositories_github_repo ON repositories(github_repo);
CREATE INDEX IF NOT EXISTS idx_scans_repo_id ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo_id_created_at ON scans(repo_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_commit_sha ON scans(commit_sha);
CREATE INDEX IF NOT EXISTS idx_scans_overall_risk_score ON scans(overall_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_package_name ON vulnerabilities(package_name);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_risk_score ON vulnerabilities(risk_score DESC);

-- Views for common queries
CREATE OR REPLACE VIEW repository_latest_scans AS
SELECT DISTINCT ON (r.id) 
    r.id as repo_id,
    r.github_repo,
    r.name as repo_name,
    r.language,
    s.id as scan_id,
    s.overall_risk_score,
    s.total_vulnerabilities,
    s.high_risk_count,
    s.medium_risk_count,
    s.low_risk_count,
    s.created_at as last_scan_time
FROM repositories r
LEFT JOIN scans s ON r.id = s.repo_id
ORDER BY r.id, s.created_at DESC;

CREATE OR REPLACE VIEW organization_summary AS
SELECT 
    o.id as org_id,
    o.github_org,
    o.name as org_name,
    COUNT(DISTINCT r.id) as total_repositories,
    COUNT(DISTINCT s.id) as total_scans,
    AVG(s.overall_risk_score) as average_risk_score,
    SUM(s.total_vulnerabilities) as total_vulnerabilities,
    COUNT(DISTINCT CASE WHEN s.overall_risk_score >= 7.0 THEN r.id END) as high_risk_repos,
    MAX(s.created_at) as last_scan_time
FROM organizations o
LEFT JOIN repositories r ON o.id = r.org_id
LEFT JOIN scans s ON r.id = s.repo_id
GROUP BY o.id, o.github_org, o.name;

-- Function to calculate risk trend
CREATE OR REPLACE FUNCTION get_risk_trend(repo_id_param INTEGER, days_param INTEGER DEFAULT 30)
RETURNS TABLE(
    date_point DATE,
    avg_risk_score DECIMAL(3,1),
    vuln_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        DATE(s.created_at) as date_point,
        AVG(s.overall_risk_score)::DECIMAL(3,1) as avg_risk_score,
        COUNT(v.id) as vuln_count
    FROM scans s
    LEFT JOIN vulnerabilities v ON s.id = v.scan_id
    WHERE s.repo_id = repo_id_param
        AND s.created_at >= NOW() - INTERVAL '%s days' % days_param
    GROUP BY DATE(s.created_at)
    ORDER BY date_point;
END;
$$ LANGUAGE plpgsql;