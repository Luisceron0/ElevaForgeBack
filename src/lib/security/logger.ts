/**
 * Structured security event logger.
 *
 * OWASP A09:2025 — Security Logging & Alerting Failures
 *
 * Rules:
 *  - Never log PII, credentials, or full request bodies.
 *  - Always include IP (hashed in production if needed), path, and timestamp.
 *  - Use deterministic event types for easy alerting rules.
 */

export type SecurityEventType =
  | 'CSRF_VIOLATION'
  | 'RATE_LIMIT_EXCEEDED'
  | 'VALIDATION_FAILURE'
  | 'HONEYPOT_TRIGGERED'
  | 'OVERSIZED_PAYLOAD'
  | 'INVALID_CONTENT_TYPE'
  | 'MALFORMED_BODY'
  | 'SCANNER_PROBE'
  | 'BLOCKED_PATH'
  | 'UNHANDLED_ERROR'

export interface SecurityEvent {
  type: SecurityEventType
  ip: string
  path: string
  method?: string
  details?: string
}

/**
 * Log a security-relevant event as structured JSON.
 */
export function logSecurityEvent(event: SecurityEvent): void {
  const entry = {
    level: 'SECURITY',
    ts: new Date().toISOString(),
    ...event,
  }
  console.warn(JSON.stringify(entry))
}
