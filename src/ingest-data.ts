export interface IIngestDataRequest {
  request: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body: string;
  };
  response: {
    headers: Record<string, string>;
    status: number;
    statusText: string;
    body: string;
  };
  time?: number;
}

export class IngestDataRequest implements IIngestDataRequest {
  request: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body: string;
  };
  response: {
    headers: Record<string, string>;
    status: number;
    statusText: string;
    body: string;
  };
  time?: number;

  constructor(
    url: string,
    method: string,
    requestHeaders: Record<string, string>,
    requestBody: string,
    responseHeaders: Record<string, string>,
    status: number,
    statusText: string,
    responseBody: string,
    time?: number
  ) {
    this.request = {
      url,
      method,
      headers: requestHeaders,
      body: requestBody
    };
    this.response = {
      headers: responseHeaders,
      status,
      statusText,
      body: responseBody
    };
    this.time = time;
  }
}

export interface IngestDataResult {
  success: boolean;
  message: string;
  captured: boolean;
}

export function ingestData(
  ingestDataRequest: IngestDataRequest,
  env: any,
  ctx: ExecutionContext
): IngestDataResult {
  try {
    console.log("Input ingestDataRequest:", JSON.stringify(ingestDataRequest, null, 2));

    const contentType = (ingestDataRequest.request.headers["content-type"] || "").toLowerCase();
    const isAllowed = isAllowedContentType(contentType);
    const shouldCapture = isAllowed && isValidStatus(ingestDataRequest.response.status);

    if (!shouldCapture) {
      console.log("Traffic not captured. ContentType allowed:", isAllowed, "Status valid:", isValidStatus(ingestDataRequest.response.status));
      return {
        success: true,
        message: `Traffic not captured. ContentType allowed: ${isAllowed}, Status valid: ${isValidStatus(ingestDataRequest.response.status)}`,
        captured: false
      };
    }

    ctx.waitUntil((async () => {
      try {
        const logs = generateLogFromPayload(ingestDataRequest);
        console.log("Payload sent to queue:", logs);
        await sendToQueue(logs, env);
      } catch (error) {
        console.error("Error processing traffic in background:", error);
      }
    })());

    return {
      success: true,
      message: "Traffic successfully queued for processing",
      captured: true
    };
  } catch (error) {
    console.error("Error ingesting data:", error);
    return {
      success: false,
      message: `Error ingesting data: ${error instanceof Error ? error.message : 'Unknown error'}`,
      captured: false
    };
  }
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

export function generateLogFromPayload(payload: IngestDataRequest): string {
  const url = new URL(payload.request.url);
  const timestamp = payload.time ? Math.round(payload.time / 1000) : Math.round(Date.now() / 1000);
  const value = {
    path: url.pathname,
    requestHeaders: JSON.stringify(payload.request.headers),
    responseHeaders: JSON.stringify(payload.response.headers),
    method: payload.request.method,
    requestPayload: payload.request.body,
    responsePayload: payload.response.body,
    ip: payload.request.headers["x-forwarded-for"] || payload.request.headers["cf-connecting-ip"] || payload.request.headers["x-real-ip"] || "",
    time: timestamp.toString(),
    statusCode: payload.response.status.toString(),
    type: "HTTP/1.1",
    status: payload.response.statusText,
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
