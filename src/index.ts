import { Container, getRandom } from "@cloudflare/containers";
import { collectTraffic, duplicateRequest } from "./akto-wrapper";
import { ingestData, IngestDataRequest, IIngestDataRequest, IngestDataResult } from "./ingest-data";

export class Backend extends Container {
  defaultPort = 8080; // pass requests to port 8080 in the container
  sleepAfter = "2h"; // only sleep a container if it hasn't gotten requests in 2 hours
  maxStartupTime = "60s"; // allow more time for container startup
  
  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    // Pass environment variables to the container
    this.envVars = {
      MCP_LLM_API_KEY: env.MCP_LLM_API_KEY || "",
      LIBONNX_RUNTIME_PATH: env.LIBONNX_RUNTIME_PATH || "/usr/local/lib/libonnxruntime.so",
      DEBUG: env.DEBUG || "false"
    };
  }
}

export interface Env {
  BACKEND: DurableObjectNamespace<Backend>;
  // Environment variables
  MCP_LLM_API_KEY?: string;
  LIBONNX_RUNTIME_PATH?: string;
  DEBUG?: string;
}


const INSTANCE_COUNT = 3;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }

    if (url.pathname === "/ingest-data") {
      try {
        // create IngestDataPayload from request
        // todo: handle auth and database abstractor token based ingestion
        const requestBody = await request.json() as IIngestDataRequest;

        // Validate required fields
        if (!requestBody.host || !requestBody.url || !requestBody.method) {
          return new Response(JSON.stringify({
            error: "Missing required fields: host, url, and method are mandatory"
          }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (!requestBody.requestHeaders || !requestBody.responseHeaders) {
          return new Response(JSON.stringify({
            error: "Missing required fields: requestHeaders and responseHeaders are mandatory"
          }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (typeof requestBody.responseStatus !== 'number') {
          return new Response(JSON.stringify({
            error: "responseStatus must be a number"
          }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
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
          requestBody.time
        );

        const result = ingestData(ingestDataRequest, env, ctx);

        if (!result.success) {
          return new Response(JSON.stringify({ error: result.message }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response(JSON.stringify({
          message: result.message,
          captured: result.captured
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });

      } catch (error) {
        console.error("Error processing ingest-data request:", error);

        if (error instanceof SyntaxError) {
          return new Response(JSON.stringify({
            error: "Invalid JSON in request body"
          }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }

        return new Response(JSON.stringify({
          error: "Internal server error while processing request"
        }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    
    const containerInstance = await getRandom(env.BACKEND, INSTANCE_COUNT);
    return containerInstance.fetch(request);
  },
};
