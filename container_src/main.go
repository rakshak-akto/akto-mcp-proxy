package main

import (
	"bufio"
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

// ProxyServer holds the server configuration
type ProxyServer struct {
	logger *log.Logger
	client *http.Client
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer() *ProxyServer {
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

	return &ProxyServer{
		logger: log.New(os.Stdout, "", 0),
		client: client,
	}
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

// extractSNIHost extracts the host part for SNI (removes port)
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

// proxyHandler handles the main proxy logic for /proxy/<scheme>/<host>/<path>
func (ps *ProxyServer) proxyHandler(w http.ResponseWriter, r *http.Request) {
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

	// Create the proxy request
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Set proxy headers (matching nginx config)
	sniHost := extractSNIHost(targetHost)
	proxyReq.Host = sniHost
	proxyReq.Header.Set("Host", sniHost)
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	proxyReq.Header.Set("X-Forwarded-Proto", scheme)
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	// Copy specific headers from original request
	headersToForward := []string{
		"Authorization", "Content-Type", "User-Agent", "Cookie",
	}
	for _, header := range headersToForward {
		if value := r.Header.Get(header); value != "" {
			proxyReq.Header.Set(header, value)
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
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length,Content-Range")
	w.Header().Set("X-Accel-Buffering", "no")

	// Copy response headers, but ensure SSE-specific headers are set correctly
	for key, values := range resp.Header {
		// Skip headers that might interfere with SSE streaming
		if strings.ToLower(key) == "content-length" {
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
		// For SSE, we need to stream and rewrite line by line
		ps.streamSSEWithRewrite(w, resp.Body, targetScheme, targetHost)
	} else {
		// For non-SSE content, stream directly
		io.Copy(w, resp.Body)
	}
}

// optionsHandler handles CORS preflight requests
func (ps *ProxyServer) optionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func main() {
	server := NewProxyServer()

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", server.healthHandler)

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
