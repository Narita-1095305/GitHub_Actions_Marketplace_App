package github

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
)

// Client wraps GitHub API client with our specific functionality
type Client struct {
	client *github.Client
	owner  string
	repo   string
	pr     int
	sha    string
}

// NewClient creates a new GitHub API client
func NewClient() (*Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	// Extract repository information from environment
	owner, repo, err := getRepoInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	pr, sha, err := getPRInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get PR info: %w", err)
	}

	// Create OAuth2 client
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	return &Client{
		client: github.NewClient(tc),
		owner:  owner,
		repo:   repo,
		pr:     pr,
		sha:    sha,
	}, nil
}

// getRepoInfo extracts owner and repo from GITHUB_REPOSITORY
func getRepoInfo() (string, string, error) {
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return "", "", fmt.Errorf("GITHUB_REPOSITORY environment variable is required")
	}

	// Parse "owner/repo" format
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid GITHUB_REPOSITORY format: %s", repo)
	}

	return parts[0], parts[1], nil
}

// getPRInfo extracts PR number and SHA from environment
func getPRInfo() (int, string, error) {
	// Get PR number
	prStr := os.Getenv("GITHUB_PR_NUMBER")
	if prStr == "" {
		// Try to extract from GITHUB_REF for pull_request events
		ref := os.Getenv("GITHUB_REF")
		if strings.HasPrefix(ref, "refs/pull/") {
			parts := strings.Split(ref, "/")
			if len(parts) >= 3 {
				prStr = parts[2]
			}
		}
	}

	var pr int
	var err error
	if prStr != "" {
		pr, err = strconv.Atoi(prStr)
		if err != nil {
			return 0, "", fmt.Errorf("invalid PR number: %s", prStr)
		}
	}

	// Get SHA
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" {
		return 0, "", fmt.Errorf("GITHUB_SHA environment variable is required")
	}

	return pr, sha, nil
}

// GetRepoInfo returns repository information
func (c *Client) GetRepoInfo() (string, string) {
	return c.owner, c.repo
}

// GetPRInfo returns PR information
func (c *Client) GetPRInfo() (int, string) {
	return c.pr, c.sha
}