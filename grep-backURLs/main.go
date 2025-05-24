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


// getFileSize returns the size of a file in bytes.
func getFileSize(filename string) int64 {
	info, err := os.Stat(filename)
	if err != nil {
		return 0 // Return 0 on error
	}
	return info.Size()
}

// runCommand executes an external command with a timeout.
func runCommand(cmd *exec.Cmd, description string) error {
	logMessage("INFO", fmt.Sprintf("Running %s...", description))

	var cmdDone = make(chan error)
	go func() {
		cmdDone <- cmd.Run()
	}()

	select {
	case err := <-cmdDone:
		if err != nil {
			errMsg := fmt.Sprintf("Error running %s: %v", description, err)
			logMessage("ERROR", errMsg)
			mu.Lock()
			results.Errors = append(results.Errors, errMsg)
			mu.Unlock()
			return err
		}
	case <-time.After(time.Duration(config.Timeout) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill() // Terminate the process if it times out
		}
		errMsg := fmt.Sprintf("Command %s timed out after %d seconds.", description, config.Timeout)
		logMessage("ERROR", errMsg)
		mu.Lock()
		results.Errors = append(results.Errors, errMsg)
		mu.Unlock()
		return fmt.Errorf(errMsg)
	}

	logMessage("INFO", fmt.Sprintf("%s completed successfully.", description))
	return nil
}

// analyzeURL parses a raw URL and extracts relevant information.
func analyzeURL(rawURL string) URLAnalysis {
	analysis := URLAnalysis{URL: rawURL}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		logMessage("WARN", fmt.Sprintf("Failed to parse URL %s: %v", rawURL, err))
		return analysis
	}

	analysis.Domain = parsedURL.Host
	analysis.Path = parsedURL.Path

	for param := range parsedURL.Query() {
		analysis.Parameters = append(analysis.Parameters, param)
	}

	if ext := filepath.Ext(parsedURL.Path); ext != "" {
		analysis.Extensions = append(analysis.Extensions, ext)
	}

	// Removed hardcoded sensitivePatterns and their logic as per user request.
	// The 'Sensitive' field in URLAnalysis will now always be its zero value (false).

	return analysis
}

// processKeywords processes wayback content against a list of keywords concurrently.
func processKeywords(waybackContent []byte, keywords []string, domain string) ([]PatternResult, error) {
	// Filtering logic removed as per user request. All URLs from waybackContent will be processed.
	urls := strings.Split(string(waybackContent), "\n")

	analyses := make([]URLAnalysis, 0, len(urls)) // Changed from filteredURLs to urls
	for _, rawURL := range urls {                 // Changed from filteredURLs to urls
		if strings.TrimSpace(rawURL) != "" {
			analysis := analyzeURL(rawURL)
			analyses = append(analyses, analysis)
		}
	}

	analysisFile := filepath.Join(config.OutputDir, fmt.Sprintf("%s_url_analysis.json", domain))
	analysisData, err := json.MarshalIndent(analyses, "", "  ")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Error marshalling URL analysis: %v", err))
		return nil, fmt.Errorf("error marshalling URL analysis: %v", err)
	}
	if err := os.WriteFile(analysisFile, analysisData, 0644); err != nil {
		logMessage("ERROR", fmt.Sprintf("Error saving URL analysis to %s: %v", analysisFile, err))
		return nil, fmt.Errorf("error saving URL analysis: %v", err)
	}
	logMessage("INFO", fmt.Sprintf("URL analysis saved to: %s", analysisFile))

	var allPatternResults []PatternResult

	var wg sync.WaitGroup
	patternChan := make(chan string, len(keywords))

	for i := 0; i < config.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for keyword := range patternChan {
				keyword = strings.TrimSpace(keyword)
				if keyword == "" || strings.HasPrefix(keyword, "#") {
					continue
				}

				pattern, err := parsePattern(keyword)
				if err != nil {
					logMessage("WARN", fmt.Sprintf("Skipping invalid pattern '%s': %v", keyword, err))
					continue
				}

				safeName := strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
						return r
					}
					return '_'
				}, pattern.original)

				resultFile := filepath.Join(config.OutputDir, fmt.Sprintf("%s_%s_results.txt", domain, safeName))
				jsonResultFile := filepath.Join(config.OutputDir, fmt.Sprintf("%s_%s_results.json", domain, safeName))
				markdownResultFile := filepath.Join(config.OutputDir, fmt.Sprintf("%s_%s_results.md", domain, safeName))

				var matches []string
				scanner := bufio.NewScanner(strings.NewReader(string(waybackContent)))
				for scanner.Scan() {
					line := scanner.Text()
					if pattern.regex.MatchString(line) {
						matches = append(matches, line)
					}
				}

				if len(matches) > 0 {
					fmt.Printf("%sProcessing pattern:%s %s\n", colorCyan, colorReset, pattern.original)
					for _, match := range matches {
						fmt.Printf("%s\n", match)
					}

					patternResult := PatternResult{
						OriginalPattern:  pattern.original,
						RegexPattern:     pattern.regex.String(),
						MatchedLines:     matches,
						ResultFilePath:   resultFile,
						JSONFilePath:     jsonResultFile,
						MarkdownFilePath: markdownResultFile,
					}

					if err := os.WriteFile(resultFile, []byte(strings.Join(matches, "\n")), 0644); err != nil {
						logMessage("ERROR", fmt.Sprintf("Error saving raw results for pattern %s: %v", pattern.original, err))
					}

					jsonData, err := json.MarshalIndent(patternResult, "", "  ")
					if err != nil {
						logMessage("ERROR", fmt.Sprintf("Error marshalling JSON for pattern %s: %v", pattern.original, err))
					} else if err := os.WriteFile(jsonResultFile, jsonData, 0644); err != nil {
						logMessage("ERROR", fmt.Sprintf("Error saving JSON results for pattern %s: %v", pattern.original, err))
					}

					var mdContent strings.Builder
					mdContent.WriteString(fmt.Sprintf("# Results for Pattern: `%s`\n\n", pattern.original))
					mdContent.WriteString(fmt.Sprintf("Compiled Regex: `%s`\n\n", pattern.regex.String()))
					mdContent.WriteString("## Matched Lines:\n\n")
					for _, line := range matches {
						mdContent.WriteString(fmt.Sprintf("- `%s`\n", line))
					}
					if err := os.WriteFile(markdownResultFile, []byte(mdContent.String()), 0644); err != nil {
						logMessage("ERROR", fmt.Sprintf("Error saving Markdown results for pattern %s: %v", pattern.original, err))
					}

					mu.Lock()
					results.MatchCount[pattern.original] = len(matches)
					allPatternResults = append(allPatternResults, patternResult)
					mu.Unlock()
				}
			}
		}()
	}

	for _, kw := range keywords {
		patternChan <- kw
	}
	close(patternChan)

	wg.Wait()

	return allPatternResults, nil
}

// generateReport creates the final JSON report and optionally an HTML report.
func generateReport(domain string, allPatternResults []PatternResult, generateHTML bool) error {
	results.Domain = domain
	results.Timestamp = time.Now() // Timestamp for the overall scan results

	mu.Lock()
	totalMatches := 0
	for _, count := range results.MatchCount {
		totalMatches += count
	}
	results.Statistics["total_matches"] = totalMatches
	results.Statistics["total_patterns"] = len(results.MatchCount)
	mu.Unlock()

	reportFile := filepath.Join(config.OutputDir, fmt.Sprintf("%s_report.json", domain))
	reportData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling final report JSON: %v", err)
	}

	if err := os.WriteFile(reportFile, reportData, 0644); err != nil {
		return fmt.Errorf("error saving final JSON report: %v", err)
	}
	logMessage("INFO", fmt.Sprintf("Final JSON report generated: %s", reportFile))

	if generateHTML {
		if err := generateHTMLReport(allPatternResults, domain); err != nil {
			return fmt.Errorf("error generating HTML report: %v", err)
		}
	}

	return nil
}

// currentTimestamp returns a formatted string of the current time.
// This function is kept because it's used for the HTML report's GeneratedTime.
func currentTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05 MST")
}

// generateHTMLReport creates a comprehensive HTML report.
func generateHTMLReport(resultsData []PatternResult, domain string) error {
	// Generate the HTML report inside the config.OutputDir
	reportFilePath := filepath.Join(config.OutputDir, fmt.Sprintf("report_%s.html", domain))

	// The HTML template string is embedded here.
	const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report for {{.Domain}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; background-color: #f4f4f4; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #0056b3; }
        .pattern-section { border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px; padding: 15px; background-color: #f9f9f9; }
        .pattern-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
        .pattern-header h3 { margin: 0; }
        .content { display: none; margin-top: 10px; padding-left: 20px; border-left: 3px solid #eee; }
        .content.active { display: block; }
        ul { list-style-type: none; padding: 0; }
        li { background: #e9e9e9; margin-bottom: 5px; padding: 8px; border-radius: 3px; word-wrap: break-word; }
        .summary-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .summary-table th, .summary-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .summary-table th { background-color: #007bff; color: white; }
        .links a { margin-right: 10px; text-decoration: none; color: #007bff; }
        .links a:hover { text-decoration: underline; }
        .toggle-icon { font-weight: bold; }
        .no-matches { color: #888; font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Report for <code>{{.Domain}}</code></h1>
        <p>Generated on: {{.GeneratedTime}}</p>

        <h2>Summary of Findings</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Pattern</th>
                    <th>Matches Found</th>
                    <th>Links</th>
                </tr>
            </thead>
            <tbody>
                {{range .Results}}
                <tr>
                    <td><code>{{.OriginalPattern}}</code></td>
                    <td>{{len .MatchedLines}}</td>
                    <td>
                        <div class="links">
                            {{if .ResultFilePath}}<a href="{{base .ResultFilePath}}" target="_blank">Raw Text</a>{{end}}
                            {{if .JSONFilePath}}<a href="{{base .JSONFilePath}}" target="_blank">JSON</a>{{end}}
                            {{if .MarkdownFilePath}}<a href="{{base .MarkdownFilePath}}" target="_blank">Markdown</a>{{end}}
                        </div>
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <h2>Detailed Results</h2>
        {{range .Results}}
        <div class="pattern-section">
            <div class="pattern-header" onclick="toggleContent(this)">
                <h3>Pattern: <code>{{.OriginalPattern}}</code> (Matches: {{len .MatchedLines}})</h3>
                <span class="toggle-icon">+</span>
            </div>
            <div class="content">
                <p><strong>Compiled Regex:</strong> <code>{{.RegexPattern}}</code></p>
                {{if .ResultFilePath}}<p><strong>Raw Output File:</strong> <a href="{{base .ResultFilePath}}" target="_blank">{{base .ResultFilePath}}</a></p>{{end}}
                {{if .JSONFilePath}}<p><strong>JSON Output File:</strong> <a href="{{base .JSONFilePath}}" target="_blank">{{base .JSONFilePath}}</a></p>{{end}}
                {{if .MarkdownFilePath}}<p><strong>Markdown Output File:</strong> <a href="{{base .MarkdownFilePath}}" target="_blank">{{base .MarkdownFilePath}}</a></p>{{end}}
                {{if .MatchedLines}}
                    <h4>Matched Lines (first 10):</h4>
                    <ul>
                        {{range $i, $line := .MatchedLines}}
                            {{if lt $i 10}}<li><code>{{$line}}</code></li>{{end}}
                        {{end}}
                        {{if gt (len .MatchedLines) 10}}<li>... ({{sub (len .MatchedLines) 10}} more lines)</li>{{end}}
                    </ul>
                {{else}}
                    <p class="no-matches">No matches found for this pattern.</p>
                {{end}}
            </div>
        </div>
        {{end}}
    </div>

    <script>
        function toggleContent(header) {
            const content = header.nextElementSibling;
            const icon = header.querySelector('.toggle-icon');
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                icon.textContent = '+';
            } else {
                content.classList.add('active');
                icon.textContent = '-';
            }
        }
    </script>
</body>
</html>
`
	// ReportData struct for HTML template
	type ReportData struct {
		Domain        string
		GeneratedTime string
		Results       []PatternResult
	}

	reportData := ReportData{
		Domain:        domain,
		GeneratedTime: currentTimestamp(),
		Results:       resultsData,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"sub":  func(a, b int) int { return a - b },
		"base": filepath.Base,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("error parsing HTML template: %v", err)
	}

	file, err := os.Create(reportFilePath)
	if err != nil {
		return fmt.Errorf("error creating HTML report file: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, reportData); err != nil {
		return fmt.Errorf("error executing HTML template: %v", err)
	}

	logMessage("INFO", fmt.Sprintf("HTML report generated at: %s", reportFilePath))
	return nil
}

func printBanner() {
	banner := fmt.Sprintf(`%s
╔══════════════════════════════════════════════════════════════╗
║             %sEnhanced URL Reconnaissance Tool%s             ║
║                       %s v%s %s                              ║
╚══════════════════════════════════════════════════════════════╝
%s`, colorCyan, colorBold, colorReset+colorCyan, colorBold, version, colorReset+colorCyan, colorReset)
	fmt.Println(banner)
}

// printUsage displays the tool's usage instructions and options.
func printUsage() {
	fmt.Printf(`%sUsage:%s
  %s [options]%s

%sA tool to find sensitive information by enumerating subdomains, collecting Wayback Machine URLs,
analyzing them, and matching against custom patterns.%s

%sOptions:%s
`, colorYellow, colorReset, os.Args[0], colorReset, colorReset, colorReset, colorGreen, colorReset)
	flag.PrintDefaults()
	fmt.Printf(`
%sExamples:%s
  %s -domain example.com -html
  %s -domain target.com -keywords-file custom_keywords.txt -json -markdown
  %s -domain example.org
  %s -v
  %s --config (to generate a default config.json or modify existing)
`, colorGreen, colorReset, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

// main function is the entry point of the program.
func main() {
	var domainFlag string
	var keywordsFileFlag string
	var outputDirFlag string
	var generateJSONFlag bool
	var generateMarkdownFlag bool
	var generateHTMLFlag bool
	var showVersionFlag bool
	var configSetupFlag bool

	// Define flags
	flag.StringVar(&domainFlag, "domain", "", "Specify the target domain (e.g., example.com)")
	flag.StringVar(&keywordsFileFlag, "keywords-file", "grep_keywords.txt", "Path to a file containing grep-like keywords (one per line)")
	flag.StringVar(&outputDirFlag, "output-dir", "output", "Base directory to store all scan output files")
	flag.BoolVar(&generateJSONFlag, "json", false, "Generate results in JSON format for each pattern")
	flag.BoolVar(&generateMarkdownFlag, "markdown", false, "Generate results in Markdown format for each pattern")
	flag.BoolVar(&generateHTMLFlag, "html", false, "Generate a comprehensive HTML report summarizing all findings in the current directory")
	flag.BoolVar(&showVersionFlag, "version", false, "Display the tool version and exit")
	flag.BoolVar(&showVersionFlag, "v", false, "Display the tool version and exit (shorthand)")
	flag.BoolVar(&configSetupFlag, "config", false, "Run interactive configuration setup and exit")

	flag.Usage = printUsage // Set custom usage function

	flag.Parse() // Parse command-line arguments here

	if showVersionFlag {
		fmt.Printf("grep-backURLs Version: %s\n", version)
		return
	}

	if configSetupFlag {
		logMessage("INFO", "Starting interactive configuration setup...")
		if err := loadConfig(); err != nil { // loadConfig will now also save the updated timestamp
			logMessage("ERROR", fmt.Sprintf("Failed to load/create config: %v", err))
			return
		}
		logMessage("INFO", "Configuration setup complete. Modify config.json manually if needed.")
		return
	}

	// Load configuration (will also update config.Timestamp and save it)
	if err := loadConfig(); err != nil {
		logMessage("ERROR", fmt.Sprintf("Error loading config: %v", err))
		return
	}

	// Store the original config.OutputDir loaded from the file
	originalConfigOutputDir := config.OutputDir

	// --- CRITICAL MODIFICATION: Check and STOP if -output-dir flag overrides config ---
	var outputDirFlagWasProvided bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "output-dir" {
			outputDirFlagWasProvided = true
		}
	})

	if outputDirFlagWasProvided {
		if outputDirFlag != originalConfigOutputDir {
			logMessage("ERROR", fmt.Sprintf("Command-line flag '-output-dir %s' differs from 'output_dir' in config.json ('%s').", outputDirFlag, originalConfigOutputDir))
			logMessage("ERROR", "Please update 'output_dir' in your config.json to match the desired output directory, then run the tool again.")
			logMessage("ERROR", "Exiting to ensure consistent configuration.")
			return // Exit the program
		}
	}
	// If the flag was provided and matches, or if it wasn't provided,
	// config.OutputDir will already hold the correct value (either from flag or config).
	// No explicit assignment needed here unless you want to force the flag value even if it matches config.
	if outputDirFlagWasProvided {
		config.OutputDir = outputDirFlag
	}
	// --- END CRITICAL MODIFICATION ---

	// Override domain setting with command-line flag if provided
	if domainFlag != "" {
		config.Domain = domainFlag
	}

	// Prompt for domain if not provided via flag or config
	if config.Domain == "" {
		fmt.Printf("%sEnter the target domain (e.g., example.com): %s", colorBold, colorReset)
		fmt.Scanln(&config.Domain)
	}

	// Final check for domain
	if config.Domain == "" {
		logMessage("ERROR", "Domain cannot be empty. Exiting.")
		flag.Usage()
		return
	}
	results.Domain = config.Domain // Set domain in results struct

	// Create output directory
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		logMessage("ERROR", fmt.Sprintf("Error creating output directory %s: %v", config.OutputDir, err))
		return
	}
	logMessage("INFO", fmt.Sprintf("All output will be saved to: %s", config.OutputDir))

	// Setup logging to file
	if err := setupLogging(config.Domain); err != nil {
		logMessage("WARN", fmt.Sprintf("Failed to set up logging: %v. Proceeding without file logging.", err))
	}
	defer func() {
		if logFile != nil {
			logFile.Close() // Ensure log file is closed on exit
		}
	}()

	// --- MODIFICATION: Define file paths for subfinder and waybackurls output in the current working directory ---
	cwd, _ := os.Getwd()
	subFile := filepath.Join(cwd, fmt.Sprintf("%s_subdomains.txt", config.Domain))
	waybackFile := filepath.Join(cwd, fmt.Sprintf("%s_waybackurls.txt", config.Domain))
	// --- END MODIFICATION ---

	// Check if keywords file exists
	if _, err := os.Stat(keywordsFileFlag); os.IsNotExist(err) {
		logMessage("ERROR", fmt.Sprintf("Keywords file '%s' not found. Please create it with one keyword per line.", keywordsFileFlag))
		return
	}

	var wg sync.WaitGroup

	// --- MODIFICATION: Use Subfinder only ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd := exec.Command("subfinder", "-d", config.Domain, "-o", subFile)
		if err := runCommand(cmd, "Subfinder"); err != nil {
			logMessage("ERROR", fmt.Sprintf("Subfinder failed for %s: %v. Cannot proceed without subdomains. Exiting.", config.Domain, err))
			os.Exit(1) // Exit if subfinder fails, as waybackurls depends on it
		}
	}()
	wg.Wait() // Wait for Subfinder to complete

	// Check if subdomains were found
	if isEmptyFile(subFile) {
		logMessage("ERROR", fmt.Sprintf("No subdomains found in '%s' or Subfinder failed to populate it. Cannot proceed with Waybackurls. Exiting.", subFile))
		return
	}

	// Read subdomains and update results
	subContent, err := os.ReadFile(subFile)
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Error reading subdomains file '%s': %v", subFile, err))
		return
	}
	results.SubdomainCount = len(strings.Split(strings.TrimSpace(string(subContent)), "\n"))
	if results.SubdomainCount == 1 && strings.TrimSpace(string(subContent)) == "" { // Handle case of empty file but split gives 1 empty string
		results.SubdomainCount = 0
	}
	logMessage("INFO", fmt.Sprintf("Found %d subdomains.", results.SubdomainCount))

	// Run Waybackurls concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd := exec.Command("waybackurls")
		file, err := os.Open(subFile)
		if err != nil {
			logMessage("ERROR", fmt.Sprintf("Error opening subdomain file '%s' for waybackurls: %v", subFile, err))
			return
		}
		defer file.Close()
		cmd.Stdin = file // Pipe subdomains to waybackurls stdin
		outFile, err := os.Create(waybackFile)
		if err != nil {
			logMessage("ERROR", fmt.Sprintf("Error creating wayback file '%s': %v", waybackFile, err))
			return
		}
		defer outFile.Close()
		cmd.Stdout = outFile // Redirect waybackurls stdout to file
		if err := runCommand(cmd, "Waybackurls"); err != nil {
			logMessage("WARN", fmt.Sprintf("Waybackurls failed for %s: %v. Proceeding with potentially empty Wayback URLs file.", config.Domain, err))
		}
	}()
	wg.Wait() // Wait for Waybackurls to complete

	// Read wayback URLs and update results
	waybackContent, err := os.ReadFile(waybackFile)
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Error reading wayback file '%s': %v", waybackFile, err))
		return
	}
	results.URLCount = len(strings.Split(strings.TrimSpace(string(waybackContent)), "\n"))
	if results.URLCount == 1 && strings.TrimSpace(string(waybackContent)) == "" { // Handle case of empty file
		results.URLCount = 0
	}
	logMessage("INFO", fmt.Sprintf("Collected %d Wayback URLs.", results.URLCount))

	logMessage("INFO", "Processing keywords and patterns...")
	keywordsContent, err := os.ReadFile(keywordsFileFlag)
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Error reading grep keywords file '%s': %v", keywordsFileFlag, err))
		return
	}

	allKeywords := append(strings.Split(string(keywordsContent), "\n"), config.CustomKeywords...)

	allPatternResults, err := processKeywords(waybackContent, allKeywords, config.Domain)
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Error processing keywords: %v", err))
		return
	}

	logMessage("INFO", "Generating reports...")
	if err := generateReport(config.Domain, allPatternResults, generateHTMLFlag); err != nil {
		logMessage("ERROR", fmt.Sprintf("Error generating reports: %v", err))
		return
	}

	// Print final summary banner
	fmt.Printf(`
%s╔══════════════════════════════════════════════════════════════╗
║                       %sSUMMARY%s                              ║
╠════════════════════════════════════════════════════════════════╣
║ Domain:             %-42s ║                                    ║
║ Subdomains Found:   %-42d ║                                    ║
║ URLs Collected:     %-42d ║                                    ║
║ Total Matches:      %-42d ║                                    ║
║ Output Directory:   %-42s ║                                    ║
╚══════════════════════════════════════════════════════════════╝%s

%sAutomation script completed successfully!%s
`, colorGreen, colorBold, colorReset+colorGreen, config.Domain, results.SubdomainCount, results.URLCount,
		results.Statistics["total_matches"], config.OutputDir, colorReset, colorBold, colorReset)
}
