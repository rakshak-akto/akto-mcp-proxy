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
      // create IngestDataPayload from request
      // todo: handle auth and database abstractor token based ingestion
      const requestBody = await request.json() as IIngestDataRequest;

      const ingestDataRequest = new IngestDataRequest(
        requestBody.request.url,
        requestBody.request.method,
        requestBody.request.headers,
        requestBody.request.body,
        requestBody.response.headers,
        requestBody.response.status,
        requestBody.response.statusText,
        requestBody.response.body,
        requestBody.time
      );

      ingestData(ingestDataRequest, env, ctx);
      return new Response("Ingested", { status: 200 });
    }
    
    const containerInstance = await getRandom(env.BACKEND, INSTANCE_COUNT);
    return containerInstance.fetch(request);
  },
};
