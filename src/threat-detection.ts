export interface ThreatDetectionMetadata {
  countryCode?: string;
  [key: string]: any;
}

export interface MaliciousEvent {
  actor: string;
  filterId: string;
  detectedAt: string;
  latestApiIp: string;
  latestApiEndpoint: string;
  latestApiMethod: string;
  latestApiCollectionId: number;
  latestApiPayload: string;
  eventType: string;
  category: string;
  subCategory: string;
  severity: string;
  type: string;
  metadata: ThreatDetectionMetadata;
}

export interface ThreatDetectionRequest {
  maliciousEvent: MaliciousEvent;
}

export interface ThreatDetectionResult {
  success: boolean;
  message: string;
}

export interface ThreatDetectionConfig {
  endpoint: string;
  bearerToken: string;
}

function createMaliciousEventPayload(
  ingestDataRequest: any,
  threatInfo: Partial<MaliciousEvent>
): MaliciousEvent {
  const timestamp = Date.now().toString();
  const url = new URL(ingestDataRequest.url);

  const requestPayload = JSON.stringify({
    method: ingestDataRequest.method,
    requestPayload: ingestDataRequest.requestBody,
    responsePayload: ingestDataRequest.responseBody,
    ip: getClientIp(ingestDataRequest.requestHeaders),
    destIp: getClientIp(ingestDataRequest.requestHeaders),
    source: "OTHER",
    type: "HTTP/2",
    akto_vxlan_id: "",
    path: url.pathname,
    requestHeaders: JSON.stringify(ingestDataRequest.requestHeaders),
    responseHeaders: JSON.stringify(ingestDataRequest.responseHeaders),
    time: 0,
    akto_account_id: "",
    statusCode: ingestDataRequest.responseStatus,
    status: ingestDataRequest.responseStatusText || "OK"
  });

  return {
    actor: getClientIp(ingestDataRequest.requestHeaders),
    filterId: threatInfo.filterId || "UnknownThreat",
    detectedAt: timestamp,
    latestApiIp: getClientIp(ingestDataRequest.requestHeaders),
    latestApiEndpoint: url.pathname,
    latestApiMethod: ingestDataRequest.method,
    latestApiCollectionId: parseInt(timestamp.slice(-10)),
    latestApiPayload: requestPayload,
    eventType: threatInfo.eventType || "EVENT_TYPE_SINGLE",
    category: threatInfo.category || "Security",
    subCategory: threatInfo.subCategory || "Security",
    severity: threatInfo.severity || "MEDIUM",
    type: threatInfo.type || "Rule-Based",
    metadata: threatInfo.metadata || {}
  };
}

function getClientIp(requestHeaders: Record<string, string>): string {
  const normalizedHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(requestHeaders)) {
    normalizedHeaders[key.toLowerCase()] = value;
  }

  return normalizedHeaders["x-forwarded-for"] ||
         normalizedHeaders["cf-connecting-ip"] ||
         normalizedHeaders["x-real-ip"] ||
         normalizedHeaders["x-client-ip"] ||
         "0.0.0.0";
}

export async function recordMaliciousEvent(
  ingestDataRequest: any,
  threatInfo: Partial<MaliciousEvent>,
  config: ThreatDetectionConfig
): Promise<ThreatDetectionResult> {
  try {
    const maliciousEvent = createMaliciousEventPayload(ingestDataRequest, threatInfo);

    const requestPayload: ThreatDetectionRequest = {
      maliciousEvent
    };

    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.bearerToken}`,
        'x-akto-ignore': 'true',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestPayload)
    });

    if (!response.ok) {
      throw new Error(`Threat detection API returned ${response.status}: ${response.statusText}`);
    }

    return {
      success: true,
      message: "Malicious event recorded successfully"
    };
  } catch (error) {
    console.error("Error recording malicious event:", error);
    return {
      success: false,
      message: `Error recording malicious event: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

export function shouldTriggerThreatDetection(
  ingestDataRequest: any,
  responseBody: string
): Partial<MaliciousEvent> | null {
  try {
    let responseData: any;

    // Try to parse response body as JSON
    try {
      responseData = JSON.parse(responseBody);
    } catch {
      // If not JSON, return null
      return null;
    }

    // Check if policy_action is "block"
    if (responseData && responseData.policy_action === "block") {
      return {
        filterId: "PolicyViolation",
        category: "Security",
        subCategory: "PolicyViolation",
        severity: "HIGH",
        type: "Rule-Based",
        eventType: "EVENT_TYPE_SINGLE"
      };
    }

    return null;
  } catch (error) {
    console.error("Error in threat detection analysis:", error);
    return null;
  }
}