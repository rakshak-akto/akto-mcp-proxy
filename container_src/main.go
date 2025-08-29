package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type ProxyServer struct {
	servers   map[string]*ServerConfig
	serversMu sync.RWMutex
	upgrader  websocket.Upgrader
}

type ServerConfig struct {
	Name      string
	HTTPUrl   string
	WSUrl     string
	SSEUrl    string
	Transport string // "http", "websocket", "sse"
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		servers: make(map[string]*ServerConfig),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
	}
}

func (p *ProxyServer) RegisterServer(name string, config *ServerConfig) {
	p.serversMu.Lock()
	defer p.serversMu.Unlock()
	p.servers[name] = config
	log.Printf("Registered MCP server: %s with transport: %s", name, config.Transport)
}

func (p *ProxyServer) getServerConfig(name string) (*ServerConfig, bool) {
	p.serversMu.RLock()
	defer p.serversMu.RUnlock()
	config, exists := p.servers[name]
	return config, exists
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse the path to extract server name
	pathRegex := regexp.MustCompile(`^/([^/]+)/?(.*)$`)
	matches := pathRegex.FindStringSubmatch(r.URL.Path)
	
	if len(matches) < 2 {
		http.Error(w, "Invalid path format. Expected: /mcp-server-name/...", http.StatusBadRequest)
		return
	}

	serverName := matches[1]
	remainingPath := ""
	if len(matches) > 2 {
		remainingPath = matches[2]
	}

	config, exists := p.getServerConfig(serverName)
	if !exists {
		http.Error(w, fmt.Sprintf("MCP server '%s' not found", serverName), http.StatusNotFound)
		return
	}

	log.Printf("Forwarding request to %s (transport: %s, path: %s)", serverName, config.Transport, remainingPath)

	// Handle different transport protocols
	switch strings.ToLower(config.Transport) {
	case "websocket", "ws":
		p.handleWebSocket(w, r, config, remainingPath)
	case "sse", "server-sent-events":
		p.handleSSE(w, r, config, remainingPath)
	case "http", "https":
		fallthrough
	default:
		p.handleHTTP(w, r, config, remainingPath)
	}
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request, config *ServerConfig, remainingPath string) {
	targetURL, err := url.Parse(config.HTTPUrl)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Create new request URL
	targetURL.Path = "/" + remainingPath
	targetURL.RawQuery = r.URL.RawQuery

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Customize the director to handle MCP-specific headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		
		// Add MCP-specific headers
		req.Header.Set("X-MCP-Proxy", "true")
		req.Header.Set("X-Original-Host", r.Host)
		
		// Preserve important headers
		if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		
		// Handle MCP protocol headers
		if mcpVersion := r.Header.Get("MCP-Version"); mcpVersion != "" {
			req.Header.Set("MCP-Version", mcpVersion)
		}
	}

	// Handle errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error for %s: %v", config.Name, err)
		http.Error(w, "Upstream server error", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

func (p *ProxyServer) handleWebSocket(w http.ResponseWriter, r *http.Request, config *ServerConfig, remainingPath string) {
	// Check if this is a WebSocket upgrade request
	if !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "Expected WebSocket upgrade", http.StatusBadRequest)
		return
	}

	// Construct target WebSocket URL
	targetURL := config.WSUrl
	if remainingPath != "" {
		targetURL = strings.TrimSuffix(targetURL, "/") + "/" + remainingPath
	}
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Upgrade client connection
	clientConn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade client connection: %v", err)
		return
	}
	defer clientConn.Close()

	// Connect to target server
	targetConn, _, err := websocket.DefaultDialer.Dial(targetURL, r.Header)
	if err != nil {
		log.Printf("Failed to connect to target WebSocket: %v", err)
		return
	}
	defer targetConn.Close()

	log.Printf("WebSocket proxy established: client <-> %s", config.Name)

	// Bidirectional message forwarding
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward messages from client to target
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Client connection error: %v", err)
				}
				break
			}
			
			if err := targetConn.WriteMessage(messageType, message); err != nil {
				log.Printf("Error forwarding to target: %v", err)
				break
			}
		}
	}()

	// Forward messages from target to client
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := targetConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Target connection error: %v", err)
				}
				break
			}
			
			if err := clientConn.WriteMessage(messageType, message); err != nil {
				log.Printf("Error forwarding to client: %v", err)
				break
			}
		}
	}()

	wg.Wait()
	log.Printf("WebSocket proxy connection closed for %s", config.Name)
}

func (p *ProxyServer) handleSSE(w http.ResponseWriter, r *http.Request, config *ServerConfig, remainingPath string) {
	// Construct target SSE URL
	targetURL := config.SSEUrl
	if remainingPath != "" {
		targetURL = strings.TrimSuffix(targetURL, "/") + "/" + remainingPath
	}
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Create request to target server
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Make request to target
	client := &http.Client{
		Timeout: 0, // No timeout for SSE
	}
	
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	// Copy other headers from response
	for key, values := range resp.Header {
		if key != "Content-Length" {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Stream response
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	buffer := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				log.Printf("Error writing to client: %v", writeErr)
				break
			}
			flusher.Flush()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading from target: %v", err)
			break
		}
	}
}

func main() {
	proxy := NewProxyServer()

	// Example server configurations
	// In production, these would be loaded from environment variables or config file
	proxy.RegisterServer("mcp-server-1", &ServerConfig{
		Name:      "mcp-server-1",
		HTTPUrl:   getEnvOrDefault("MCP_SERVER_1_HTTP", "http://localhost:8001"),
		WSUrl:     getEnvOrDefault("MCP_SERVER_1_WS", "ws://localhost:8001/ws"),
		SSEUrl:    getEnvOrDefault("MCP_SERVER_1_SSE", "http://localhost:8001/sse"),
		Transport: getEnvOrDefault("MCP_SERVER_1_TRANSPORT", "http"),
	})

	proxy.RegisterServer("mcp-server-2", &ServerConfig{
		Name:      "mcp-server-2",
		HTTPUrl:   getEnvOrDefault("MCP_SERVER_2_HTTP", "http://localhost:8002"),
		WSUrl:     getEnvOrDefault("MCP_SERVER_2_WS", "ws://localhost:8002/ws"),
		SSEUrl:    getEnvOrDefault("MCP_SERVER_2_SSE", "http://localhost:8002/sse"),
		Transport: getEnvOrDefault("MCP_SERVER_2_TRANSPORT", "websocket"),
	})

	proxy.RegisterServer("mcp-server-3", &ServerConfig{
		Name:      "mcp-server-3",
		HTTPUrl:   getEnvOrDefault("MCP_SERVER_3_HTTP", "http://localhost:8003"),
		WSUrl:     getEnvOrDefault("MCP_SERVER_3_WS", "ws://localhost:8003/ws"),
		SSEUrl:    getEnvOrDefault("MCP_SERVER_3_SSE", "http://localhost:8003/sse"),
		Transport: getEnvOrDefault("MCP_SERVER_3_TRANSPORT", "sse"),
	})

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy","timestamp":"`)
		fmt.Fprint(w, time.Now().Format(time.RFC3339))
		fmt.Fprint(w, `"}`)
	})

	// Status endpoint
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		proxy.serversMu.RLock()
		defer proxy.serversMu.RUnlock()
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		fmt.Fprint(w, `{"servers":{`)
		first := true
		for name, config := range proxy.servers {
			if !first {
				fmt.Fprint(w, ",")
			}
			first = false
			fmt.Fprintf(w, `"%s":{"transport":"%s","http":"%s","ws":"%s","sse":"%s"}`, 
				name, config.Transport, config.HTTPUrl, config.WSUrl, config.SSEUrl)
		}
		fmt.Fprint(w, `}}`)
	})

	// All other requests go through the proxy
	http.Handle("/", proxy)

	port := getEnvOrDefault("PORT", "8080")
	server := &http.Server{
		Addr:           ":" + port,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down proxy server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("MCP Proxy Server starting on port %s", port)
	log.Printf("Health check: http://localhost:%s/health", port)
	log.Printf("Status: http://localhost:%s/status", port)
	
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// package main

// import (
// 	"encoding/json"
// 	"log"
// 	"net/http"
// )

// func handler(w http.ResponseWriter, r *http.Request) {
// 	widgets := []map[string]interface{}{
// 		{"id": 1, "name": "Widget A"},
// 		{"id": 2, "name": "Widget B"},
// 		{"id": 3, "name": "Widget C"},
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	json.NewEncoder(w).Encode(widgets)
// }

// func main() {
// 	http.HandleFunc("/api/widgets", handler)
// 	log.Fatal(http.ListenAndServe(":8080", nil))
// }
