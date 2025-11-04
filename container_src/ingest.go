package main

import (
	"net/http"
	"time"
)

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

// createIngestDataPayload creates an IngestDataPayload from request and response data
func createIngestDataPayload(proxyReq *http.Request, resp *http.Response, requestBody, responseBody string) *IngestDataPayload {
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
