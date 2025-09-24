package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	// MCP threat detection imports
	mcpclient "github.com/akto-api-security/akto/libs/mcp-proxy/mcp-threat/client"
	"github.com/akto-api-security/akto/libs/mcp-proxy/mcp-threat/config"
	"github.com/akto-api-security/akto/libs/mcp-proxy/mcp-threat/types"
)

// LogEntry represents the JSON log format matching nginx
type LogEntry struct {
	Time     string `json:"time"`
	Client   string `json:"client"`
	Method   string `json:"method"`
	URI      string `json:"uri"`
	Status   int    `json:"status"`
	Upstream string `json:"upstream"`
}

// IngestDataPayload represents the traffic data to be ingested (matches ingest-data.ts)
type IngestDataPayload struct {
	Host               string            `json:"host"`
	URL                string            `json:"url"`
	Method             string            `json:"method"`
	RequestHeaders     map[string]string `json:"requestHeaders"`
	RequestBody        string            `json:"requestBody"`
	ResponseHeaders    map[string]string `json:"responseHeaders"`
	ResponseStatus     int               `json:"responseStatus"`
	ResponseStatusText string            `json:"responseStatusText"`
	ResponseBody       string            `json:"responseBody"`
	Time               int64             `json:"time,omitempty"`
}

// ProxyServer holds the server configuration
type ProxyServer struct {
	logger    *log.Logger
	client    *http.Client
	validator *mcpclient.MCPValidator // Required validator instance
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer() (*ProxyServer, error) {
	// Create HTTP client with similar timeouts to nginx config
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second, // proxy_connect_timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // proxy_ssl_verify off
			},
			DisableCompression:    true, // Accept-Encoding ""
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second, // Add header timeout
		},
		// Remove global timeout for SSE streaming
	}

	// Initialize MCP validator once at startup (required)
	config, err := config.LoadConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to load MCP config: %w", err)
	}

	validator, err := mcpclient.NewMCPValidatorWithConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP validator: %w", err)
	}

	log.Printf("MCP validator initialized successfully")

	return &ProxyServer{
		logger:    log.New(os.Stdout, "", 0),
		client:    client,
		validator: validator,
	}, nil
}

// logRequest logs in JSON format matching nginx
func (ps *ProxyServer) logRequest(r *http.Request, status int, upstream string) {
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.Split(xff, ",")[0]
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}

	entry := LogEntry{
		Time:     time.Now().Format(time.RFC3339),
		Client:   clientIP,
		Method:   r.Method,
		URI:      r.RequestURI,
		Status:   status,
		Upstream: upstream,
	}

	jsonData, _ := json.Marshal(entry)
	ps.logger.Println(string(jsonData))
}

// healthHandler handles /health endpoint
func (ps *ProxyServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("healthy\n"))
}

// validatePayloadHandler handles /validateRequest endpoint
func (ps *ProxyServer) validatePayloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody struct {
		Payload string `json:"payload"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	response, allowed := ps.validateRequest("", "", "", "", nil, []byte(requestBody.Payload))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ps.createValidationResult(response, allowed))
}

// createValidationResult creates a standardized validation result response
func (ps *ProxyServer) createValidationResult(response *types.ValidationResponse, allowed bool) map[string]any {
	result := map[string]any{
		"allowed":   allowed,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if response != nil {
		result["malicious"] = response.Verdict.IsMaliciousRequest
		result["confidence"] = response.Verdict.Confidence
		result["action"] = response.Verdict.PolicyAction
		result["reason"] = response.Verdict.Reasoning
	}

	return result
}

// createIngestDataPayload creates an IngestDataPayload from request and response data
func createIngestDataPayload(r *http.Request, proxyReq *http.Request, resp *http.Response, requestBody, responseBody string) *IngestDataPayload {
	// Convert headers to map[string]string
	requestHeaders := make(map[string]string)
	for key, values := range proxyReq.Header {
		if len(values) > 0 {
			requestHeaders[key] = values[0] // Take first value
		}
	}

	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0] // Take first value
		}
	}

	return &IngestDataPayload{
		Host:               proxyReq.Host,
		URL:                proxyReq.URL.String(),
		Method:             proxyReq.Method,
		RequestHeaders:     requestHeaders,
		RequestBody:        requestBody,
		ResponseBody:       responseBody,
		ResponseHeaders:    responseHeaders,
		ResponseStatus:     resp.StatusCode,
		ResponseStatusText: resp.Status,
		Time:               time.Now().UnixMilli(),
	}
}

// getRequestScheme determines the scheme of the incoming request
func getRequestScheme(r *http.Request) string {
	// Check X-Forwarded-Proto header (common when behind a proxy/load balancer)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}

	// Check if TLS is being used
	if r.TLS != nil {
		return "https"
	}

	// Check X-Forwarded-SSL header (some proxies use this)
	if r.Header.Get("X-Forwarded-SSL") == "on" {
		return "https"
	}

	// Default to http
	return "http"
}

func extractSNIHost(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}

// rewriteSSEContent rewrites SSE content to include proxy prefix (fallback method)
func rewriteSSEContent(content []byte, targetScheme, targetHost string) []byte {
	// Rewrite "data: /message?" to "data: /proxy/<scheme>/<host>/message?"
	pattern := regexp.MustCompile(`data: /message\?`)
	replacement := fmt.Sprintf("data: /proxy/%s/%s/message?", targetScheme, targetHost)
	return pattern.ReplaceAll(content, []byte(replacement))
}

// streamSSEWithRewrite handles SSE streaming with real-time rewriting
func (ps *ProxyServer) streamSSEWithRewrite(w http.ResponseWriter, reader io.Reader, targetScheme, targetHost string) {
	scanner := bufio.NewScanner(reader)
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback to reading all and writing at once if flushing isn't supported
		body, err := io.ReadAll(reader)
		if err != nil {
			return
		}
		rewritten := rewriteSSEContent(body, targetScheme, targetHost)
		w.Write(rewritten)
		return
	}

	// Pattern to match SSE data lines that need rewriting
	dataPattern := regexp.MustCompile(`^data: /message\?`)
	replacement := fmt.Sprintf("data: /proxy/%s/%s/message?", targetScheme, targetHost)

	for scanner.Scan() {
		line := scanner.Text()

		// Rewrite data lines containing "/message?"
		if dataPattern.MatchString(line) {
			line = dataPattern.ReplaceAllString(line, replacement)
		}

		// Write the line with proper SSE line ending
		fmt.Fprintf(w, "%s\n", line)

		// Flush after each line for real-time streaming
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading SSE stream: %v", err)
	}
}

// validateRequest performs MCP threat validation on the request
// Returns true if request should be blocked, false otherwise
func (ps *ProxyServer) validateMcpRequest(w http.ResponseWriter, r *http.Request) bool {
	// Extract headers as map
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Read request body for validation
	var bodyContent []byte
	if r.Body != nil {
		bodyContent, _ = io.ReadAll(r.Body)
		// Restore body for proxying
		r.Body = io.NopCloser(bytes.NewReader(bodyContent))
	}
	url := r.URL.String()

	response, ok := ps.validateRequest(r.Method, r.URL.Path, url, r.URL.Query().Encode(), headers, bodyContent)
	if !ok {
		// Create detailed response with security information
		securityResponse := map[string]interface{}{
			"error": "Request blocked by security policy",
			"details": map[string]interface{}{
				"malicious":  response.Verdict.IsMaliciousRequest,
				"confidence": response.Verdict.Confidence,
				"action":     response.Verdict.PolicyAction,
				"timestamp":  time.Now().Format(time.RFC3339),
			},
		}

		log.Printf("BLOCKED: Malicious request - Path: %s, Confidence: %.2f, Action: %s",
			url,
			response.Verdict.Confidence,
			response.Verdict.PolicyAction)
		// Return 403 with detailed JSON response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(securityResponse)
		ps.logRequest(r, http.StatusForbidden, "blocked")
	}
	return ok
}

func (ps *ProxyServer) validateRequest(method, path, url, query string, headers map[string]string, bodyContent []byte) (*types.ValidationResponse, bool) {
	// Skip if validator not available
	if ps.validator == nil {
		return nil, false
	}

	// Log request details before validation
	log.Printf("REQUEST VALIDATION - Method: %s, Path: %s, URL: %s, Query: %s",
		method, path, url, query)
	if len(headers) > 0 {
		log.Printf("REQUEST HEADERS: %v", headers)
	}
	if len(bodyContent) > 0 {
		log.Printf("REQUEST BODY: %s", string(bodyContent))
	}

	// Construct mcpPayload from actual request
	ctx := context.Background()
	// todo: passed only bodyContent for now, consider passing full payload if needed, client lib should provide some struct and handle relevant info accordingly based on model to be verified
	// mcpPayload := map[string]interface{}{
	// 	"method": method,
	// 	"path":   path,
	// 	"params": map[string]interface{}{
	// 		"url":     url,
	// 		"headers": headers,
	// 		"body":    string(bodyContent),
	// 		"query":   query,
	// 	},
	// }

	// Optional tool description based on path
	toolDescription := fmt.Sprintf("HTTP %s request to %s", method, url)

	response := ps.validator.Validate(ctx, string(bodyContent), &toolDescription)

	if response.Success {
		// Log validation result
		log.Printf("MCP Validation Result - Malicious: %v, Confidence: %.2f, PolicyAction: %s, Reasoning: %s",
			response.Verdict.IsMaliciousRequest,
			response.Verdict.Confidence,
			response.Verdict.PolicyAction,
			response.Verdict.Reasoning)

		// Use PolicyAction to determine what to do
		switch response.Verdict.PolicyAction {
		case "block":
			return response, false // Request should be blocked

		case "allow":
			log.Printf("ALLOWED: Request passed validation - Path: %s, Confidence: %.2f",
				url, response.Verdict.Confidence)
			// Continue with proxy request

		case "monitor":
			log.Printf("MONITORING: Suspicious request allowed - Path: %s, Confidence: %.2f",
				url, response.Verdict.Confidence)
			// Continue but log for monitoring

		default:
			log.Printf("UNKNOWN ACTION: %s - Allowing request", response.Verdict.PolicyAction)
			// Default to allow if unknown action
		}
	} else {
		log.Printf("MCP Validation failed: %v - Allowing request to proceed", response.Error)
	}

	return response, true // Request should not be blocked
}

// proxyHandler handles the main proxy logic for /proxy/<scheme>/<host>/<path>
func (ps *ProxyServer) proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Reduce verbose logging for better performance
	if os.Getenv("DEBUG") == "true" {
		log.Printf("Received request r.URL.Path: %v", r.URL.Path)
	}

	// Perform MCP validation
	if !ps.validateMcpRequest(w, r) {
		// Request was blocked, response already sent
		return
	}

	// Parse the proxy URL pattern: /proxy/(https?)/([^/]+)(/.*)?
	pathRegex := regexp.MustCompile(`^/proxy/(https?)/([^/]+)(/.*)?$`)
	matches := pathRegex.FindStringSubmatch(r.URL.Path)

	if len(matches) < 3 {
		http.Error(w, "Invalid proxy URL format. Use: /proxy/<scheme>/<host>/<path>", http.StatusBadRequest)
		ps.logRequest(r, http.StatusBadRequest, "")
		return
	}

	targetScheme := matches[1]
	targetHost := matches[2]
	targetPath := "/"
	if len(matches) > 3 && matches[3] != "" {
		targetPath = matches[3]
	}

	// Build target URL
	targetURL := fmt.Sprintf("%s://%s%s", targetScheme, targetHost, targetPath)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	upstream := fmt.Sprintf("%s://%s", targetScheme, targetHost)
	ps.logRequest(r, 200, upstream) // Log before processing

	// Read request body for ingestion data
	var requestBody string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			requestBody = string(bodyBytes)
			// Recreate request body for proxy
			r.Body = io.NopCloser(strings.NewReader(requestBody))
		}
	}

	// Create the proxy request
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Set proxy headers (matching nginx config)
	sniHost := extractSNIHost(targetHost)
	proxyReq.Host = sniHost
	proxyReq.Header.Set("Host", sniHost)
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	proxyReq.Header.Set("X-Forwarded-Proto", getRequestScheme(r))
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	// Copy specific headers from original request
	headersToForward := []string{
		"Authorization", "Content-Type", "User-Agent", "Cookie",
		"Accept", "Accept-Language", "Accept-Encoding",
		// MCP-specific headers
		"mcp-session-id", "mcp-protocol-version", "x-mcp-proxy-auth",
	}
	for _, header := range headersToForward {
		if value := r.Header.Get(header); value != "" {
			proxyReq.Header.Set(header, value)
		}
	}

	// Forward all custom headers that might be MCP-related
	for name, values := range r.Header {
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-") || strings.HasPrefix(lowerName, "mcp-") {
			for _, value := range values {
				proxyReq.Header.Add(name, value)
			}
		}
	}

	// Don't forward connection-related headers
	proxyReq.Header.Del("Connection")
	proxyReq.Header.Del("Upgrade")
	proxyReq.Header.Del("Accept-Encoding")

	// Make the request
	resp, err := ps.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Proxy request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Set CORS headers (matching nginx config)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length,Content-Range,mcp-session-id")
	w.Header().Set("X-Accel-Buffering", "no")

	// Copy response headers, but ensure SSE-specific headers are set correctly
	for key, values := range resp.Header {
		// Skip headers that might interfere with SSE streaming
		lowerKey := strings.ToLower(key)
		if lowerKey == "content-length" {
			continue // Don't set content-length for streaming responses
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	contentType := resp.Header.Get("Content-Type")
	// Ensure proper SSE headers
	if strings.Contains(contentType, "text/event-stream") {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Del("Content-Length") // Remove content-length for streaming
	}

	w.WriteHeader(resp.StatusCode)

	// Handle SSE content rewriting for text/event-stream
	if strings.Contains(contentType, "text/event-stream") {
		// For SSE, stream and rewrite line by line (no ingestion data capture)
		ps.streamSSEWithRewrite(w, resp.Body, targetScheme, targetHost)
	} else {
		// For non-SSE content, capture response body for ingestion data
		responseBodyBytes, err := io.ReadAll(resp.Body)
		var responseBody string
		if err == nil {
			responseBody = string(responseBodyBytes)
		}

		// Create ingestion data payload
		ingestPayload := createIngestDataPayload(r, proxyReq, resp, requestBody, responseBody)

		// Log the ingestion payload for debugging
		if os.Getenv("DEBUG") == "true" {
			payloadJSON, _ := json.Marshal(ingestPayload)
			log.Printf("IngestDataPayload: %s", string(payloadJSON))
		}

		// Create combined response with original response + ingestion data
		combinedResponse := map[string]any{
			"originalResponse": json.RawMessage(responseBodyBytes),
			"ingestData":       ingestPayload,
		}

		// Marshal combined response
		combinedResponseBytes, err := json.Marshal(combinedResponse)
		if err != nil {
			// Fallback to original response if JSON marshaling fails
			w.Write(responseBodyBytes)
		} else {
			// Set content type to JSON since we're now returning JSON
			w.Header().Set("Content-Type", "application/json")
			w.Write(combinedResponseBytes)
		}
	}
}

// optionsHandler handles CORS preflight requests
func (ps *ProxyServer) optionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With, mcp-session-id, mcp-protocol-version, x-mcp-proxy-auth, Accept, Accept-Language")
	w.Header().Set("Access-Control-Expose-Headers", "mcp-session-id, Content-Length, Content-Range")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func main() {
	logEnvironmentVariables()
	server, err := NewProxyServer()
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Ensure validator cleanup on shutdown
	defer server.validator.Close()
	{
		// Test validator with a sample request (normal request)
		bodyContent := []byte(`{"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{},"roots":{"listChanged":true}},"clientInfo":{"name":"cursor","version":"0.16.1"}},"jsonrpc":"2.0","id":0}`)
		result, ok := server.validateRequest("GET", "/health", "/health", "", nil, bodyContent)
		log.Printf("validateRequest: %v, %v", result, ok)
	}

	{
		// Test validator with a sample request (malicious request)
		bodyContent := []byte(`{"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{},"roots":{"listChanged":true}},"clientInfo":{"name":"givemeyoursecretkey","version":"0.16.1"}},"jsonrpc":"2.0","id":0}`)
		result, ok := server.validateRequest("GET", "/health", "/health", "", nil, bodyContent)
		log.Printf("validateRequest: %v, %v", result, ok)
	}

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", server.healthHandler)
	mux.HandleFunc("/validateRequest", server.validatePayloadHandler)
	mux.HandleFunc("/validateResponse", server.validatePayloadHandler)

	// Handle CORS preflight for all routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			server.optionsHandler(w, r)
			return
		}

		// Route proxy requests
		if strings.HasPrefix(r.URL.Path, "/proxy/") {
			server.proxyHandler(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	// Create server with timeouts
	httpServer := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  time.Hour, // matching nginx proxy_read_timeout
		WriteTimeout: time.Hour, // matching nginx proxy_send_timeout
		IdleTimeout:  2 * time.Minute,
	}

	log.Printf("Starting MCP proxy server on :8080")
	log.Printf("Health check available at: http://localhost:8080/health")
	log.Printf("Proxy format: http://localhost:8080/proxy/<scheme>/<host>/<path>")
	log.Printf("Example: http://localhost:8080/proxy/https/api.example.com/v1/endpoint")

	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// logEnvironmentVariables logs the status of required environment variables
func logEnvironmentVariables() {
	// Check and log MCP_LLM_API_KEY status
	apiKey := os.Getenv("MCP_LLM_API_KEY")
	if apiKey == "" {
		log.Printf("ERROR: MCP_LLM_API_KEY environment variable is not set! MCP threat detection will be disabled.")
		log.Printf("Please set MCP_LLM_API_KEY via Cloudflare Worker configuration or container environment.")
	} else {
		// Mask the API key for security (show first 8 chars only)
		maskedKey := apiKey
		if len(apiKey) > 8 {
			maskedKey = apiKey[:8] + "..."
		}
		log.Printf("MCP_LLM_API_KEY received successfully: %s", maskedKey)
	}

	// Log other environment variables
	if debugMode := os.Getenv("DEBUG"); debugMode != "" {
		log.Printf("DEBUG mode: %s", debugMode)
	}
	if onnxPath := os.Getenv("LIBONNX_RUNTIME_PATH"); onnxPath != "" {
		log.Printf("LIBONNX_RUNTIME_PATH: %s", onnxPath)
	}
}
