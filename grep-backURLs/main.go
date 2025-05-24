package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Define the tool's version for the --version flag
const version = "2.0.0"

// ANSI escape codes for colored console output
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
)

// Pattern holds the original keyword string and its compiled regular expression.
type Pattern struct {
	original string
	regex    *regexp.Regexp
}

// Config struct holds all configurable parameters for the tool.
type Config struct {
	Domain          string    `json:"domain"`
	OutputDir       string    `json:"output_dir"`
	MaxConcurrency  int       `json:"max_concurrency"`
	Timeout         int       `json:"timeout_seconds"`
	EnableLogging   bool      `json:"enable_logging"`
	EnableFiltering bool      `json:"enable_filtering"`
	CustomKeywords  []string  `json:"custom_keywords"`
	Timestamp       time.Time `json:"timestamp"`
}

// Results struct holds all collected data and statistics from a scan.
type Results struct {
	Domain         string         `json:"domain"`
	Timestamp      time.Time      `json:"timestamp"`
	SubdomainCount int            `json:"subdomain_count"`
	URLCount       int            `json:"url_count"`
	MatchCount     map[string]int `json:"match_count"`
	Statistics     map[string]int `json:"statistics"`
	Errors         []string       `json:"errors"`
}

// PatternResult struct holds the results for a specific pattern.
type PatternResult struct {
	OriginalPattern  string   `json:"pattern"`
	RegexPattern     string   `json:"regex_compiled"`
	MatchedLines     []string `json:"matched_lines"`
	ResultFilePath   string   `json:"raw_output_file"`
	JSONFilePath     string   `json:"json_output_file,omitempty"`
	MarkdownFilePath string   `json:"markdown_output_file,omitempty"`
}

// URLAnalysis struct holds detailed information extracted from a single URL.
type URLAnalysis struct {
	URL        string   `json:"url"`
	Domain     string   `json:"domain"`
	Path       string   `json:"path"`
	Parameters []string `json:"parameters"`
	Extensions []string `json:"json_extensions"`
	Sensitive  bool     `json:"sensitive"`
}

// Global variables for configuration, results, logging, and concurrency control.
var (
	config  Config
	results Results
	logFile *os.File
	mu      sync.Mutex
)


func parsePattern(keyword string) (*Pattern, error) {
	// Add debug logging
	fmt.Printf("Debug: Processing pattern: %s\n", keyword)

	// Remove leading "grep " or "egrep " if present
	pattern := strings.TrimPrefix(keyword, "grep ")
	pattern = strings.TrimPrefix(pattern, "egrep ")
	pattern = strings.Trim(pattern, "\"'") // Remove quotes

	// Convert grep pattern to Go regex
	var regexPattern string

	if strings.HasPrefix(pattern, "-") {
		// Handle grep flags
		parts := strings.Fields(pattern)
		if len(parts) > 1 {
			// Remove flags and keep the pattern
			pattern = parts[len(parts)-1]
			fmt.Printf("Debug: After removing flags: %s\n", pattern)
		}
	}

	// Handle different pattern types
	switch {
	case strings.HasPrefix(pattern, ".*"):
		regexPattern = pattern
		fmt.Printf("Debug: Wildcard pattern detected: %s\n", regexPattern)

	case strings.HasPrefix(pattern, "\\."):
		regexPattern = strings.Replace(pattern, "\\.", "\\.", -1)
		fmt.Printf("Debug: File extension pattern detected: %s\n", regexPattern)

	case strings.HasPrefix(pattern, "/"):
		// Handle path patterns
		regexPattern = regexp.QuoteMeta(pattern)
		fmt.Printf("Debug: Path pattern detected: %s\n", regexPattern)

	case strings.Contains(pattern, "(?<=") || strings.Contains(pattern, "(?="):
		// Handle lookaround assertions
		regexPattern = pattern
		fmt.Printf("Debug: Lookaround pattern detected: %s\n", regexPattern)

	case strings.Contains(pattern, "(http|https)"):
		// Handle URL patterns
		regexPattern = pattern
		fmt.Printf("Debug: URL pattern detected: %s\n", regexPattern)

	case strings.Contains(pattern, "[?&]"):
		// Handle URL parameter patterns
		regexPattern = pattern
		fmt.Printf("Debug: URL parameter pattern detected: %s\n", regexPattern)

	default:
		// Handle simple patterns and escape special characters
		if !strings.Contains(pattern, "([") && !strings.Contains(pattern, "{") {
			regexPattern = regexp.QuoteMeta(pattern)
		} else {
			regexPattern = pattern
		}
		fmt.Printf("Debug: Default pattern handling: %s\n", regexPattern)
	}

	// Add word boundaries for whole word matching if needed
	if strings.HasPrefix(keyword, "grep -w ") {
		regexPattern = "\\b" + regexPattern + "\\b"
		fmt.Printf("Debug: Added word boundaries: %s\n", regexPattern)
	}

	// Add case insensitive flag if -i was present
	var flags string
	if strings.Contains(keyword, " -i ") || strings.HasPrefix(keyword, "grep -i ") {
		flags = "(?i)"
		fmt.Printf("Debug: Added case-insensitive flag\n")
	}

	// Compile the regex
	regex, err := regexp.Compile(flags + regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %s: %v", pattern, err)
	}

	fmt.Printf("Debug: Final regex pattern: %s\n", flags+regexPattern)

	return &Pattern{
		original: keyword,
		regex:    regex,
	}, nil
}

func isEmptyFile(filename string) bool {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		fmt.Printf("Error checking file %s: %v\n", filename, err)
		return true
	}
	return fileInfo.Size() == 0
}

func runCommand(cmd *exec.Cmd, description string) error {
	fmt.Printf("Running %s...\n", description)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running %s: %v\n", description, err)
		return err
	}
	fmt.Printf("%s completed successfully.\n", description)
	return nil
}

func processKeywords(waybackContent []byte, keywords []string, domain string) error {
	for _, keyword := range keywords {
		keyword = strings.TrimSpace(keyword)
		if keyword == "" {
			continue
		}

		pattern, err := parsePattern(keyword)
		if err != nil {
			fmt.Printf("Warning: Skipping invalid pattern '%s': %v\n", keyword, err)
			continue
		}

		fmt.Printf("\n%sProcessing pattern: %s%s\n", colorCyan, pattern.original, colorReset)

		// Create results file
		safeName := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '_'
		}, pattern.original)
		resultFile := fmt.Sprintf("%s_%s_results.txt", domain, safeName)

		var results []string
		scanner := bufio.NewScanner(strings.NewReader(string(waybackContent)))
		for scanner.Scan() {
			line := scanner.Text()
			if pattern.regex.MatchString(line) {
				results = append(results, line)
				fmt.Println(line)
			}
		}

		if len(results) > 0 {
			if err := os.WriteFile(resultFile, []byte(strings.Join(results, "\n")), 0644); err != nil {
				return fmt.Errorf("error saving results for pattern %s: %v", pattern.original, err)
			}
		}
	}
	return nil
}

func main() {
	var domain string
	fmt.Print("Enter the domain or URL (e.g., example.com): ")
	fmt.Scanln(&domain)

	if domain == "" {
		fmt.Println("Domain cannot be empty. Exiting.")
		return
	}

	subFile := fmt.Sprintf("%s_subs.txt", domain)
	waybackFile := fmt.Sprintf("%s_wayback.txt", domain)
	grepKeywordsFile := "grep_keywords.txt"

	if _, err := os.Stat(grepKeywordsFile); os.IsNotExist(err) {
		fmt.Printf("Error: %s file not found\n", grepKeywordsFile)
		return
	}

	var wg sync.WaitGroup

	// Step 1: Run Subfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd := exec.Command("subfinder", "-d", domain, "-o", subFile)
		if err := runCommand(cmd, "Subfinder"); err != nil {
			return
		}
	}()

	wg.Wait()

	if isEmptyFile(subFile) {
		fmt.Println("No subdomains found. Exiting.")
		return
	}

	// Step 2: Run Waybackurls
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd := exec.Command("waybackurls")

		file, err := os.Open(subFile)
		if err != nil {
			fmt.Printf("Error opening subdomain file: %v\n", err)
			return
		}
		defer file.Close()

		cmd.Stdin = file
		outFile, err := os.Create(waybackFile)
		if err != nil {
			fmt.Printf("Error creating wayback file: %v\n", err)
			return
		}
		defer outFile.Close()

		cmd.Stdout = outFile
		if err := runCommand(cmd, "Waybackurls"); err != nil {
			return
		}
	}()

	wg.Wait()

	if isEmptyFile(waybackFile) {
		fmt.Println("No Wayback URLs found. Exiting.")
		return
	}

	// Step 3: Process keywords
	waybackContent, err := os.ReadFile(waybackFile)
	if err != nil {
		fmt.Printf("Error reading wayback file: %v\n", err)
		return
	}

	keywords, err := os.ReadFile(grepKeywordsFile)
	if err != nil {
		fmt.Printf("Error reading grep keywords file: %v\n", err)
		return
	}

	if err := processKeywords(waybackContent, strings.Split(string(keywords), "\n"), domain); err != nil {
		fmt.Printf("Error processing keywords: %v\n", err)
		return
	}

	fmt.Println("\nAutomation script completed successfully.")
}
