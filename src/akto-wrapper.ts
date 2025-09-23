export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const [reqForFetch, reqForCollector] = await duplicateRequest(request); // At the starting of your fetch method
    const backendResponse = await fetch(reqForFetch);
    return collectTraffic(reqForCollector, backendResponse, env, ctx); // just after getting response
  },
};

export async function duplicateRequest(request: Request): Promise<[Request, Request]> {
  if (!request.body) {
    return [request, request.clone()];
  }
  const [stream1, stream2] = request.body.tee();
  const req1 = new Request(request, { body: stream1 });
  const req2 = new Request(request, { body: stream2 });
  return [req1, req2];
}

export function collectTraffic(
  request: Request,
  backendResponse: Response,
  env: any,
  ctx: ExecutionContext
): Response {
  console.log("collectTraffic - Input request:", {
    url: request.url,
    method: request.method,
    headers: Object.fromEntries(request.headers),
  });

  console.log("collectTraffic - Input response:", {
    status: backendResponse.status,
    statusText: backendResponse.statusText,
    headers: Object.fromEntries(backendResponse.headers),
  });

  const contentType = (request.headers.get("content-type") || "").toLowerCase();
  const isAllowed = isAllowedContentType(contentType);
  const shouldCapture = isAllowed && isValidStatus(backendResponse.status);

  if (!shouldCapture) {
    console.log("Traffic not captured. ContentType allowed:", isAllowed, "Status valid:", isValidStatus(backendResponse.status));
    return backendResponse;
  }

  // Split response stream
  let responseForClient: Response = backendResponse;
  let responseForLogging: ReadableStream<Uint8Array> | null = null;

  if (backendResponse.body) {
    const [respStream1, respStream2] = backendResponse.body.tee();

    // Return one response to client
    responseForClient = new Response(respStream1, {
      headers: backendResponse.headers,
      status: backendResponse.status,
      statusText: backendResponse.statusText
    });

    // Keep the other for logging
    responseForLogging = respStream2;
  }

  ctx.waitUntil((async () => {
    let requestBody = "";
    if (request.body) requestBody = await streamToString(request.body as ReadableStream<Uint8Array>); // Type assertion needed
    let responseBody = "";
    if (responseForLogging) responseBody = await streamToString(responseForLogging);

    console.log("collectTraffic - Request body:", requestBody);
    console.log("collectTraffic - Response body:", responseBody);

    const logs = generateLog(request, requestBody, backendResponse, responseBody);
    console.log("collectTraffic - Data sent to queue:", logs);
    await sendToQueue(logs, env);
  })());

  return responseForClient;
}

export function isAllowedContentType(contentType: string): boolean {
  const allowedTypes = [
    "application/json",
    "application/xml",
    "text/xml",
    "application/grpc",
    "application/x-www-form-urlencoded",
    "application/soap+xml"
  ];
  return allowedTypes.some(type => contentType.includes(type));
}

export function isValidStatus(status: number): boolean {
  return (status >= 200 && status < 300) || [301, 302, 304].includes(status);
}

export async function streamToString(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let result = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) result += decoder.decode(value, { stream: true });
  }
  return result;
}

export async function sendToAkto(
  request: Request,
  requestBody: string,
  response: Response,
  responseBody: string,
  env: any
): Promise<void> {
  const aktoAPI = "https://webhook.site/6cb858a5-1334-4429-abc9-1f8bb2954dec";
  const logs = generateLog(request, requestBody, response, responseBody);
  const aktoRequest = new Request(aktoAPI, {
    method: "POST",
    body: logs,
    headers: { "Content-Type": "application/json", "x-api-key": "MGekj2e61JVrMBW4Dv8cg68ffjzgua2TcrIzv97W" },
  });
  const aktoResponse = await fetch(aktoRequest);
  if (aktoResponse.status === 400) {
    console.error(`Akto response: ${aktoResponse.status} ${aktoResponse.statusText}, Body: ${await aktoResponse.text()}`);
  }
}

export function generateLog(
  req: Request,
  requestBody: string,
  res: Response,
  responseBody: string
): string {
  const url = new URL(req.url);
  const value = {
    path: url.pathname,
    requestHeaders: JSON.stringify(Object.fromEntries(req.headers)),
    responseHeaders: JSON.stringify(Object.fromEntries(res.headers)),
    method: req.method,
    requestPayload: requestBody,
    responsePayload: responseBody,
    ip: req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || req.headers.get("x-real-ip") || "",
    time: Math.round(Date.now() / 1000).toString(),
    statusCode: res.status.toString(),
    type: "HTTP/1.1",
    status: res.statusText,
    akto_account_id: "1000000",
    akto_vxlan_id: "0",
    is_pending: "false",
    source: "MIRRORING",
    tag: "{\n  \"service\": \"cloudflare\"\n}"
  };
  return JSON.stringify({ batchData: [value] });
}

export async function sendToQueue(logs: string, env: any): Promise<void> {
  try {
    const data = JSON.parse(logs);
    if (!data.batchData || data.batchData.length === 0) return;

    const messages = data.batchData.map((item: any) => ({
      body: JSON.stringify(item),
    }));

    await env.AKTO_TRAFFIC_QUEUE.send(messages);
    console.log(`Sent ${messages.length} message(s) to akto-traffic-queue`);
  } catch (err) {
    console.error("Failed to send to queue:", err);
  }
}
