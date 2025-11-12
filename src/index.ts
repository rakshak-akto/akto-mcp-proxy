import { Hono } from "hono";
import { ingestData, IngestDataRequest, IIngestDataRequest } from "./ingest-data";

export interface Env {
  // Queue binding
  AKTO_TRAFFIC_QUEUE_CH_ROBINSON?: Queue;
}

const app = new Hono<{ Bindings: Env }>();

// Health check endpoint
app.get("/health", (c) => {
  return c.text("OK");
});

// Traffic ingestion endpoint
app.post("/ingest-data", async (c) => {
  try {
    const requestBody = await c.req.json<IIngestDataRequest>();

    // Validate required fields
    if (!requestBody.host || !requestBody.url || !requestBody.method) {
      return c.json(
        { error: "Missing required fields: host, url, and method are mandatory" },
        400
      );
    }

    if (!requestBody.requestHeaders || !requestBody.responseHeaders) {
      return c.json(
        { error: "Missing required fields: requestHeaders and responseHeaders are mandatory" },
        400
      );
    }

    if (typeof requestBody.responseStatus !== "number") {
      return c.json({ error: "responseStatus must be a number" }, 400);
    }

    // Ensure host is in requestHeaders
    if (!requestBody.requestHeaders.host) {
      requestBody.requestHeaders.host = requestBody.host;
    }

    const ingestDataRequest = new IngestDataRequest(
      requestBody.host,
      requestBody.url,
      requestBody.method,
      requestBody.requestHeaders,
      requestBody.requestBody || "",
      requestBody.responseHeaders,
      requestBody.responseStatus,
      requestBody.responseStatusText || "",
      requestBody.responseBody || "",
      requestBody.time,
      requestBody.tag
    );

    const result = ingestData(ingestDataRequest, c.env, c.executionCtx);

    if (!result.success) {
      return c.json({ error: result.message }, 500);
    }

    return c.json({
      message: result.message,
      captured: result.captured,
    });
  } catch (error) {
    console.error("Error processing ingest-data request:", error);

    if (error instanceof SyntaxError) {
      return c.json({ error: "Invalid JSON in request body" }, 400);
    }

    return c.json({ error: "Internal server error while processing request" }, 500);
  }
});

// 404 handler
app.notFound((c) => {
  return c.json(
    {
      error: "Not Found",
      message: "This worker only handles /health and /ingest-data endpoints",
    },
    404
  );
});

export default app;
