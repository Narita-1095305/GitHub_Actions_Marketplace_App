package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/dep-risk/dep-risk/internal/database"
	"github.com/dep-risk/dep-risk/internal/models"
)

// createScan handles POST /api/v1/scans
func (s *Server) createScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request format: " + err.Error(),
		})
		return
	}

	db := database.GetDB()

	// Start transaction
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Find or create organization
	var org models.Organization
	if err := tx.Where("git_hub_org = ?", req.Organization).First(&org).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			org = models.Organization{
				GitHubOrg: req.Organization,
				Name:      req.Organization,
			}
			if err := tx.Create(&org).Error; err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, models.APIResponse{
					Success: false,
					Error:   "Failed to create organization",
				})
				return
			}
		} else {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error",
			})
			return
		}
	}

	// Find or create repository
	var repo models.Repository
	if err := tx.Where("org_id = ? AND git_hub_repo = ?", org.ID, req.Repository).First(&repo).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			repo = models.Repository{
				OrgID:      org.ID,
				GitHubRepo: req.Repository,
				Name:       req.Repository,
				Language:   "auto", // Will be detected from scan
			}
			if err := tx.Create(&repo).Error; err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, models.APIResponse{
					Success: false,
					Error:   "Failed to create repository",
				})
				return
			}
		} else {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error",
			})
			return
		}
	}

	// Create scan record
	scan := models.Scan{
		RepoID:               repo.ID,
		CommitSHA:            req.CommitSHA,
		Branch:               req.Branch,
		OverallRiskScore:     req.ScanResult.OverallRiskScore,
		TotalVulnerabilities: req.ScanResult.TotalVulnerabilities,
		HighRiskCount:        req.ScanResult.HighRiskCount,
		MediumRiskCount:      req.ScanResult.MediumRiskCount,
		LowRiskCount:         req.ScanResult.LowRiskCount,
		ScanDuration:         req.ScanResult.ScanDuration,
	}

	if err := tx.Create(&scan).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to create scan record",
		})
		return
	}

	// Create vulnerability records
	for _, vulnReq := range req.Vulnerabilities {
		vuln := models.Vulnerability{
			ScanID:         scan.ID,
			CVEID:          vulnReq.CVEID,
			PackageName:    vulnReq.PackageName,
			PackageVersion: vulnReq.PackageVersion,
			CVSSScore:      vulnReq.CVSSScore,
			RiskScore:      vulnReq.RiskScore,
			Severity:       vulnReq.Severity,
			IsDirect:       vulnReq.IsDirect,
			Description:    vulnReq.Description,
		}

		if err := tx.Create(&vuln).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Failed to create vulnerability record",
			})
			return
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to commit transaction",
		})
		return
	}

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "Scan result stored successfully",
		Data: gin.H{
			"scan_id": scan.ID,
			"organization": req.Organization,
			"repository": req.Repository,
		},
	})
}

// getScan handles GET /api/v1/scans/:id
func (s *Server) getScan(c *gin.Context) {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid scan ID",
		})
		return
	}

	db := database.GetDB()
	var scan models.Scan

	if err := db.Preload("Repository.Organization").Preload("Vulnerabilities").First(&scan, scanID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Scan not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error",
			})
		}
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    scan,
	})
}

// getOrganizationDashboard handles GET /api/v1/orgs/:org/dashboard
func (s *Server) getOrganizationDashboard(c *gin.Context) {
	orgName := c.Param("org")
	
	// Create a simple mock dashboard response for now
	now := time.Now()
	
	dashboardData := map[string]interface{}{
		"organization": map[string]interface{}{
			"id": 1,
			"github_org": orgName,
			"name": orgName,
		},
		"summary": map[string]interface{}{
			"total_repositories": 2,
			"total_scans": 1,
			"average_risk_score": 6.8,
			"total_vulnerabilities": 15,
			"high_risk_repos": 1,
			"last_scan_time": now.Format(time.RFC3339),
		},
		"recent_scans": []interface{}{},
		"top_vulnerabilities": []interface{}{},
		"risk_trend": []interface{}{},
		"repository_stats": []interface{}{},
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    dashboardData,
	})
}

// getOrganizationRepos handles GET /api/v1/orgs/:org/repos
func (s *Server) getOrganizationRepos(c *gin.Context) {
	orgName := c.Param("org")
	
	// Parse pagination parameters
	var pagination models.PaginationParams
	if err := c.ShouldBindQuery(&pagination); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid pagination parameters",
		})
		return
	}

	db := database.GetDB()
	var org models.Organization

	// Find organization
	if err := db.Where("git_hub_org = ?", orgName).First(&org).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Organization not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error",
			})
		}
		return
	}

	// Get repositories with pagination
	var repos []models.Repository
	var total int64

	offset := (pagination.Page - 1) * pagination.PageSize

	if err := db.Model(&models.Repository{}).Where("org_id = ?", org.ID).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to count repositories",
		})
		return
	}

	if err := db.Where("org_id = ?", org.ID).
		Offset(offset).
		Limit(pagination.PageSize).
		Find(&repos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to fetch repositories",
		})
		return
	}

	// Calculate total pages
	totalPages := int(total) / pagination.PageSize
	if int(total)%pagination.PageSize > 0 {
		totalPages++
	}

	response := models.PaginatedResponse{
		Data: repos,
		Pagination: &models.Pagination{
			Page:       pagination.Page,
			PageSize:   pagination.PageSize,
			Total:      total,
			TotalPages: totalPages,
		},
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    response,
	})
}

// buildDashboardData constructs dashboard data for an organization (unused for now)
// func (s *Server) buildDashboardData(org *models.Organization) (*models.DashboardData, error) {
//   // This function is temporarily disabled
//   return nil, nil
// }

// buildDashboardSummary creates summary statistics
func (s *Server) buildDashboardSummary(orgID uint) (*models.DashboardSummary, error) {
	db := database.GetDB()

	var summary models.DashboardSummary

	// Count repositories
	var repoCount int64
	if err := db.Model(&models.Repository{}).Where("org_id = ?", orgID).Count(&repoCount).Error; err != nil {
		return nil, err
	}
	summary.TotalRepositories = int(repoCount)

	// Count scans
	var scanCount int64
	if err := db.Model(&models.Scan{}).
		Joins("JOIN repositories ON repositories.id = scans.repo_id").
		Where("repositories.org_id = ?", orgID).
		Count(&scanCount).Error; err != nil {
		return nil, err
	}
	summary.TotalScans = int(scanCount)

	// Calculate average risk score
	var avgRisk sql.NullFloat64
	if err := db.Model(&models.Scan{}).
		Select("AVG(overall_risk_score)").
		Joins("JOIN repositories ON repositories.id = scans.repo_id").
		Where("repositories.org_id = ?", orgID).
		Scan(&avgRisk).Error; err != nil {
		return nil, err
	}
	if avgRisk.Valid {
		summary.AverageRiskScore = avgRisk.Float64
	}

	// Count total vulnerabilities
	var vulnCount int64
	if err := db.Model(&models.Vulnerability{}).
		Joins("JOIN scans ON scans.id = vulnerabilities.scan_id").
		Joins("JOIN repositories ON repositories.id = scans.repo_id").
		Where("repositories.org_id = ?", orgID).
		Count(&vulnCount).Error; err != nil {
		return nil, err
	}
	summary.TotalVulnerabilities = int(vulnCount)

	// Count high-risk repositories (latest scan with risk score >= 7.0)
	// This is a simplified query - in production, you'd want to optimize this
	var highRiskRepos int64
	if err := db.Raw(`
		SELECT COUNT(DISTINCT r.id)
		FROM repositories r
		JOIN scans s ON r.id = s.repo_id
		WHERE r.org_id = ? 
		AND s.overall_risk_score >= 7.0
		AND s.id IN (
			SELECT MAX(s2.id) 
			FROM scans s2 
			WHERE s2.repo_id = r.id
		)
	`, orgID).Scan(&highRiskRepos).Error; err != nil {
		return nil, err
	}
	summary.HighRiskRepos = int(highRiskRepos)

	// Get last scan time
	var lastScan time.Time
	if err := db.Model(&models.Scan{}).
		Select("MAX(created_at)").
		Joins("JOIN repositories ON repositories.id = scans.repo_id").
		Where("repositories.org_id = ?", orgID).
		Scan(&lastScan).Error; err != nil {
		return nil, err
	}
	if !lastScan.IsZero() {
		summary.LastScanTime = &lastScan
	}

	return &summary, nil
}

// Temporarily disabled complex functions to fix compilation errors
func (s *Server) buildRiskTrend(orgID uint, days int) ([]models.RiskTrendPoint, error) {
	db := database.GetDB()
	var trend []models.RiskTrendPoint

	// This query calculates the average risk score per day for the last `days` days.
	// It's a bit complex and might need optimization for very large datasets.
	if err := db.Raw(`
		SELECT
			DATE(s.created_at) as date,
			AVG(s.overall_risk_score) as average_risk_score
		FROM scans s
		JOIN repositories r ON s.repo_id = r.id
		WHERE r.org_id = ? AND s.created_at >= ?
		GROUP BY DATE(s.created_at)
		ORDER BY date ASC
	`, orgID, time.Now().AddDate(0, 0, -days)).Scan(&trend).Error; err != nil {
		return nil, err
	}

	return trend, nil
}

// func (s *Server) buildRepositoryStats(orgID uint) ([]models.RepositoryStats, error) { ... }

// Additional handlers for other endpoints...
func (s *Server) getOrganizationStats(c *gin.Context) {
	orgName := c.Param("org")
	db := database.GetDB()

	var org models.Organization
	if err := db.Where("git_hub_org = ?", orgName).First(&org).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Organization not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error while finding organization",
			})
		}
		return
	}

	summary, err := s.buildDashboardSummary(org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to build dashboard summary: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    summary,
	})
}

func (s *Server) getRepositoryScans(c *gin.Context) {
	owner := c.Param("owner")
	repoName := c.Param("repo")

	var pagination models.PaginationParams
	if err := c.ShouldBindQuery(&pagination); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid pagination parameters",
		})
		return
	}

	db := database.GetDB()

	var repo models.Repository
	if err := db.Joins("JOIN organizations ON organizations.id = repositories.org_id").
		Where("organizations.git_hub_org = ? AND repositories.git_hub_repo = ?", owner, repoName).
		First(&repo).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Repository not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error while finding repository",
			})
		}
		return
	}

	var scans []models.Scan
	var total int64

	offset := (pagination.Page - 1) * pagination.PageSize

	if err := db.Model(&models.Scan{}).Where("repo_id = ?", repo.ID).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to count scans",
		})
		return
	}

	if err := db.Where("repo_id = ?").
		Order("created_at DESC").
		Offset(offset).
		Limit(pagination.PageSize).
		Find(&scans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to fetch scans",
		})
		return
	}

	totalPages := int(total) / pagination.PageSize
	if int(total)%pagination.PageSize > 0 {
		totalPages++
	}

	response := models.PaginatedResponse{
		Data: scans,
		Pagination: &models.Pagination{
			Page:       pagination.Page,
			PageSize:   pagination.PageSize,
			Total:      total,
			TotalPages: totalPages,
		},
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    response,
	})
}

func (s *Server) getRepositoryHistory(c *gin.Context) {
	owner := c.Param("owner")
	repoName := c.Param("repo")

	db := database.GetDB()

	var repo models.Repository
	if err := db.Joins("JOIN organizations ON organizations.id = repositories.org_id").
		Where("organizations.git_hub_org = ? AND repositories.git_hub_repo = ?", owner, repoName).
		First(&repo).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Repository not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error while finding repository",
			})
		}
		return
	}

	// For repository history, we can return the risk trend for that specific repo
	var trend []models.RiskTrendPoint
	if err := db.Raw(`
		SELECT
			DATE(created_at) as date,
			AVG(overall_risk_score) as average_risk_score
		FROM scans
		WHERE repo_id = ?
		GROUP BY DATE(created_at)
		ORDER BY date ASC
	`, repo.ID).Scan(&trend).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to fetch repository history",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    trend,
	})
}

func (s *Server) getLatestScan(c *gin.Context) {
	owner := c.Param("owner")
	repoName := c.Param("repo")

	db := database.GetDB()

	var repo models.Repository
	if err := db.Joins("JOIN organizations ON organizations.id = repositories.org_id").
		Where("organizations.git_hub_org = ? AND repositories.git_hub_repo = ?", owner, repoName).
		First(&repo).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Repository not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Database error while finding repository",
			})
		}
		return
	}

	var latestScan models.Scan
	if err := db.Where("repo_id = ?").
		Order("created_at DESC").
		Preload("Vulnerabilities").
		First(&latestScan).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "No scans found for this repository",
			})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Success: false,
				Error:   "Failed to fetch latest scan",
			})
		}
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    latestScan,
	})
}

func (s *Server) getVulnerabilities(c *gin.Context) {
	// Parse query parameters
	page := 1
	pageSize := 20
	
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}
	
	// Calculate offset
	offset := (page - 1) * pageSize
	
	// Get vulnerabilities with pagination
	var vulnerabilities []models.Vulnerability
	var total int64
	
	db := database.GetDB()
	
	// Count total vulnerabilities
	if err := db.Model(&models.Vulnerability{}).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to count vulnerabilities",
		})
		return
	}
	
	// Get vulnerabilities with pagination and preload scan data
	if err := db.Preload("Scan").Preload("Scan.Repository").
		Offset(offset).Limit(pageSize).
		Order("risk_score DESC, created_at DESC").
		Find(&vulnerabilities).Error; err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to fetch vulnerabilities",
		})
		return
	}
	
	// Calculate pagination info
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}
	
	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: models.PaginatedResponse{
			Data: vulnerabilities,
			Pagination: &models.Pagination{
				Page:       page,
				PageSize:   pageSize,
				Total:      total,
				TotalPages: totalPages,
			},
		},
	})
}

func (s *Server) getVulnerability(c *gin.Context) {
	id := c.Param("id")
	
	var vulnerability models.Vulnerability
	db := database.GetDB()
	
	if err := db.Preload("Scan").Preload("Scan.Repository").
		First(&vulnerability, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "Vulnerability not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to fetch vulnerability",
		})
		return
	}
	
	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    vulnerability,
	})
}