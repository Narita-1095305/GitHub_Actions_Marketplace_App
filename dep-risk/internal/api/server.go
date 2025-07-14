package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/dep-risk/dep-risk/internal/database"
	"github.com/dep-risk/dep-risk/internal/models"
)

// Server represents the API server
type Server struct {
	router *gin.Engine
	port   string
}

// NewServer creates a new API server instance
func NewServer() *Server {
	// Set Gin mode based on environment
	if os.Getenv("ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	
	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(corsMiddleware())
	router.Use(authMiddleware())

	server := &Server{
		router: router,
		port:   getEnvOrDefault("PORT", "8080"),
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// ServeHTTP implements http.Handler interface for testing
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Health check endpoint
	s.router.GET("/health", s.healthCheck)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Scan endpoints
		v1.POST("/scans", s.createScan)
		v1.GET("/scans/:id", s.getScan)

		// Organization endpoints
		orgs := v1.Group("/orgs/:org")
		{
			orgs.GET("/dashboard", s.getOrganizationDashboard)
			orgs.GET("/repos", s.getOrganizationRepos)
			orgs.GET("/stats", s.getOrganizationStats)
		}

		// Repository endpoints
		repos := v1.Group("/repos/:owner/:repo")
		{
			repos.GET("/scans", s.getRepositoryScans)
			repos.GET("/history", s.getRepositoryHistory)
			repos.GET("/latest", s.getLatestScan)
		}

		// Vulnerability endpoints
		v1.GET("/vulnerabilities", s.getVulnerabilities)
		v1.GET("/vulnerabilities/:id", s.getVulnerability)
	}
}

// Start starts the API server
func (s *Server) Start() error {
	log.Printf("🚀 Starting API server on port %s", s.port)

	srv := &http.Server{
		Addr:    ":" + s.port,
		Handler: s.router,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Println("✅ Server exited")
	return nil
}

// Health check endpoint
func (s *Server) healthCheck(c *gin.Context) {
	// Check database connection
	if err := database.HealthCheck(); err != nil {
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{
			Success: false,
			Error:   "Database connection failed",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "API server is healthy",
		Data: gin.H{
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
			"status":    "ok",
		},
	})
}

// CORS middleware
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Basic auth middleware (will be enhanced with JWT later)
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health check and public endpoints
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		// For now, we'll implement a simple API key auth
		// In production, this should be JWT-based
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		// Allow requests without API key for development
		if os.Getenv("ENV") != "production" && apiKey == "" {
			c.Next()
			return
		}

		// Validate API key (simplified for now)
		validAPIKey := os.Getenv("API_KEY")
		if validAPIKey != "" && apiKey != validAPIKey {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Error:   "Invalid API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}