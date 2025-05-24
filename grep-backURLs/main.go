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

// init function initializes global maps before main runs.
func init() {
	results.MatchCount = make(map[string]int)
	results.Statistics = make(map[string]int)
	results.Errors = make([]string, 0)
}

// setupLogging configures the logging output to a file within the output directory.
func setupLogging(domain string) error {
	if !config.EnableLogging {
		return nil
	}

	logDir := filepath.Join(config.OutputDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory %s: %v", logDir, err)
	}

	// Log file name includes a timestamp for uniqueness
	logPath := filepath.Join(logDir, fmt.Sprintf("%s_%s.log", domain, time.Now().Format("20060102_150405")))
	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %v", logPath, err)
	}

	log.SetOutput(logFile) // Directs standard log output to the file
	return nil
}

// logMessage prints messages to console and optionally to a log file.
func logMessage(level, message string) {
	// Timestamp for individual log entries
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s: %s", timestamp, level, message)

	// Print to console with colors
	switch level {
	case "ERROR":
		fmt.Printf("%s[ERROR]%s %s\n", colorRed, colorReset, message)
	case "WARN":
		fmt.Printf("%s[WARN]%s %s\n", colorYellow, colorReset, message)
	case "INFO":
		fmt.Printf("%s[INFO]%s %s\n", colorGreen, colorReset, message)
	case "DEBUG":
		fmt.Printf("%s[DEBUG]%s %s\n", colorBlue, colorReset, message)
	default:
		fmt.Printf("%s\n", message)
	}

	// Write to log file if enabled and file is open
	if config.EnableLogging && logFile != nil {
		if _, err := logFile.WriteString(logEntry + "\n"); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write to log file: %v\n", err)
		}
	}
}

// loadConfig loads configuration from config.json or creates a default one.

func loadConfig() error {
	configFile := "config.json"
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		logMessage("INFO", "config.json not found. Creating default configuration.")
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %v", err)
		}
		config = Config{
			OutputDir:       cwd,
			MaxConcurrency:  10,
			Timeout:         300,
			EnableLogging:   true,
			EnableFiltering: true, // Default to true, but now ignored for filtering logic
			CustomKeywords:  []string{},
			Timestamp:       time.Now(), // Initial timestamp for new config
		}
		return saveConfig() // Save the newly created default config
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config data from %s: %v", configFile, err)
	}
	logMessage("INFO", fmt.Sprintf("Configuration loaded from %s.", configFile))

	// Update the timestamp to the current time whenever config is loaded
	config.Timestamp = time.Now()
	// Save the config immediately to persist the updated timestamp
	if err := saveConfig(); err != nil {
		return fmt.Errorf("failed to save config after timestamp update: %v", err)
	}

	return nil
}

// saveConfig marshals the current config to JSON and writes it to config.json.
func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %v", err)
	}
	if err := os.WriteFile("config.json", data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	logMessage("INFO", "Configuration saved to config.json.")
	return nil
}

// parsePattern parses a keyword string into a Pattern struct with a compiled regex.
func parsePattern(keyword string) (*Pattern, error) {
	pattern := strings.TrimPrefix(keyword, "grep ")
	pattern = strings.TrimPrefix(pattern, "egrep ")
	pattern = strings.Trim(keyword, "\"'")

	var regexPattern string

	originalKeywordLower := strings.ToLower(keyword)
	isWholeWord := strings.Contains(originalKeywordLower, " -w ") || strings.HasPrefix(originalKeywordLower, "grep -w ")
	isCaseInsensitive := strings.Contains(originalKeywordLower, " -i ") || strings.HasPrefix(originalKeywordLower, "grep -i ")

	if strings.HasPrefix(pattern, "-") {
		parts := strings.Fields(pattern)
		if len(parts) > 1 {
			cleanedParts := []string{}
			foundPatternStart := false
			for _, p := range parts {
				if !strings.HasPrefix(p, "-") || foundPatternStart {
					cleanedParts = append(cleanedParts, p)
					foundPatternStart = true
				}
			}
			pattern = strings.Join(cleanedParts, " ")
		}
	}

	switch {
	case strings.HasPrefix(pattern, ".*"):
		regexPattern = pattern
	case strings.HasPrefix(pattern, "\\."):
		regexPattern = pattern
	case strings.HasPrefix(pattern, "/"):
		regexPattern = regexp.QuoteMeta(pattern)
	case strings.Contains(pattern, "(?<=") || strings.Contains(pattern, "(?="):
		regexPattern = pattern
	case strings.Contains(pattern, "(http|https)"):
		regexPattern = pattern
	case strings.Contains(pattern, "[?&]"):
		regexPattern = pattern
	default:
		isComplexRegex := strings.ContainsAny(pattern, ".*+?|()[]{}^$\\")
		if isComplexRegex {
			regexPattern = pattern
		} else {
			regexPattern = regexp.QuoteMeta(pattern)
		}
	}

	if isWholeWord {
		regexPattern = "\\b" + regexPattern + "\\b"
	}

	var flags string
	if isCaseInsensitive {
		flags = "(?i)"
	}

	regex, err := regexp.Compile(flags + regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern '%s' (derived regex: '%s'): %v", keyword, flags+regexPattern, err)
	}

	return &Pattern{
		original: keyword,
		regex:    regex,
	}, nil
}

// isEmptyFile checks if a file exists and is empty.
func isEmptyFile(filename string) bool {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return true // File does not exist, so it's "empty" for our purpose
		}
		logMessage("ERROR", fmt.Sprintf("Error checking file %s: %v", filename, err))
		return true // Treat error as empty to prevent further processing
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
