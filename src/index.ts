import { Container, getRandom } from "@cloudflare/containers";

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
  async fetch(request: Request, env: Env): Promise<Response> {
    const containerInstance = await getRandom(env.BACKEND, INSTANCE_COUNT);
    return containerInstance.fetch(request);
  },
};
