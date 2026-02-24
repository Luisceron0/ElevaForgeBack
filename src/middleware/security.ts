/**
 * Security Middleware
 *
 * OWASP A01, A09 — Blocked paths, request ID, logging
 */

import type { Request, Response, NextFunction } from 'express'
import { logSecurityEvent } from '../lib/security/logger.js'

// ═══════════════════════════════════════════════════════════════
// A01:2025 — Blocked paths (force-browsing / scanner probes)
// ═══════════════════════════════════════════════════════════════
const BLOCKED_PATH_PATTERNS = [
  /\/\.git/i,
  /\/\.env/i,
  /\/\.svn/i,
  /\/\.htaccess/i,
  /\/\.htpasswd/i,
  /\/\.ds_store/i,
  /\/backup\//i,
  /\/wp-admin/i,
  /\/wp-login/i,
  /\/wp-content/i,
  /\/xmlrpc\.php/i,
  /\/phpmyadmin/i,
  /\/admin\/?$/i,
  /\/administrator/i,
  /\/web\.config/i,
  /\/server-status/i,
  /\/server-info/i,
  /\/composer\.(json|lock)/i,
  /\/package\.json/i,
  /\/package-lock\.json/i,
  /\/node_modules/i,
]

export function getClientIP(req: Request): string {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0]?.trim() || 'unknown'
  }
  return (req.socket?.remoteAddress || 'unknown')
}

export function securityMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const ip = getClientIP(req)
  const path = req.path

  // A09: Add request ID for tracing
  const requestId = crypto.randomUUID()
  res.setHeader('X-Request-Id', requestId)
  ;(req as Request & { requestId: string }).requestId = requestId

  // A01: Block sensitive / scanner-probe paths
  if (BLOCKED_PATH_PATTERNS.some((re) => re.test(path))) {
    logSecurityEvent({
      type: 'SCANNER_PROBE',
      ip,
      path,
      method: req.method,
      details: 'Blocked path access attempt',
    })
    res.status(404).json({ error: 'Not Found' })
    return
  }

  // Additional security headers not covered by Helmet
  res.setHeader('X-DNS-Prefetch-Control', 'on')
  res.setHeader('X-Download-Options', 'noopen')
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none')
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=()'
  )

  next()
}
