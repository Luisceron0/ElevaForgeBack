/**
 * CSRF Protection via Origin/Referer header validation.
 *
 * OWASP A01:2025 — Broken Access Control (CWE-352: CSRF)
 */

import type { Request } from 'express'

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((o) => o.trim())

export interface OriginCheckResult {
  valid: boolean
  reason?: string
}

export function validateOrigin(request: Request): OriginCheckResult {
  // Skip in development for local testing convenience
  if (process.env.NODE_ENV === 'development') {
    return { valid: true }
  }

  // 1. Check Origin header (most reliable)
  const origin = request.headers.origin as string | undefined
  if (origin) {
    if (ALLOWED_ORIGINS.includes(origin)) return { valid: true }
    return { valid: false, reason: `Rejected origin: ${origin}` }
  }

  // 2. Fallback to Referer header
  const referer = request.headers.referer as string | undefined
  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin
      if (ALLOWED_ORIGINS.includes(refererOrigin)) return { valid: true }
      return { valid: false, reason: `Rejected referer origin: ${refererOrigin}` }
    } catch {
      return { valid: false, reason: 'Malformed referer header' }
    }
  }

  // 3. Neither header present — reject
  return { valid: false, reason: 'Missing Origin and Referer headers' }
}
