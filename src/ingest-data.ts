export interface IIngestDataRequest {
  host: string;
  url: string;
  method: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  responseHeaders: Record<string, string>;
  responseStatus: number;
  responseStatusText: string;
  responseBody: string;
  time?: number;
}

export class IngestDataRequest implements IIngestDataRequest {
  host: string;
  url: string;
  method: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  responseHeaders: Record<string, string>;
  responseStatus: number;
  responseStatusText: string;
  responseBody: string;
  time?: number;

  constructor(
    host: string,
    url: string,
    method: string,
    requestHeaders: Record<string, string>,
    requestBody: string,
    responseHeaders: Record<string, string>,
    responseStatus: number,
    responseStatusText: string,
    responseBody: string,
    time?: number
  ) {
    this.host = host;
    this.url = url;
    this.method = method;
    this.requestHeaders = requestHeaders;
    this.requestBody = requestBody;
    this.responseHeaders = responseHeaders;
    this.responseStatus = responseStatus;
    this.responseStatusText = responseStatusText;
    this.responseBody = responseBody;
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

    const contentType = (ingestDataRequest.requestHeaders["content-type"] || "").toLowerCase();
    const isAllowed = isAllowedContentType(contentType);
    const shouldCapture = isAllowed && isValidStatus(ingestDataRequest.responseStatus);

    if (!shouldCapture) {
      console.log("Traffic not captured. ContentType allowed:", isAllowed, "Status valid:", isValidStatus(ingestDataRequest.responseStatus));
      return {
        success: true,
        message: `Traffic not captured. ContentType allowed: ${isAllowed}, Status valid: ${isValidStatus(ingestDataRequest.responseStatus)}`,
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

function isAllowedContentType(contentType: string): boolean {
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

function isValidStatus(status: number): boolean {
  return (status >= 200 && status < 300) || [301, 302, 304].includes(status);
}

function generateLogFromPayload(payload: IngestDataRequest): string {
  const url = new URL(payload.url);
  const timestamp = payload.time ? Math.round(payload.time / 1000) : Math.round(Date.now() / 1000);
  const value = {
    path: url.pathname,
    requestHeaders: JSON.stringify(payload.requestHeaders),
    responseHeaders: JSON.stringify(payload.responseHeaders),
    method: payload.method,
    requestPayload: payload.requestBody,
    responsePayload: payload.responseBody,
    ip: payload.requestHeaders["x-forwarded-for"] || payload.requestHeaders["cf-connecting-ip"] || payload.requestHeaders["x-real-ip"] || "",
    time: timestamp.toString(),
    statusCode: payload.responseStatus.toString(),
    type: "HTTP/1.1",
    status: payload.responseStatusText,
    akto_account_id: "1000000",
    akto_vxlan_id: "0",
    is_pending: "false",
    source: "MIRRORING",
    tag: "{\n  \"service\": \"cloudflare\"\n}"
  };
  return JSON.stringify({ batchData: [value] });
}

async function sendToQueue(logs: string, env: any): Promise<void> {
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
