/**
 * Rate Limiter Middleware
 *
 * OWASP A04:2025 — Insecure Design (resource exhaustion prevention)
 * Using express-rate-limit for production-ready rate limiting.
 */

import rateLimit from 'express-rate-limit'
import { logSecurityEvent } from '../lib/security/logger.js'
import { getClientIP } from './security.js'
import type { Request, Response } from 'express'

export const rateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // max 10 requests per window
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false,
  keyGenerator: (req: Request) => getClientIP(req),
  handler: (req: Request, res: Response) => {
    const ip = getClientIP(req)
    logSecurityEvent({
      type: 'RATE_LIMIT_EXCEEDED',
      ip,
      path: req.path,
      method: req.method,
    })
    res.status(429).json({
      error: 'Demasiadas solicitudes. Intenta más tarde.',
    })
  },
  skip: (req: Request) => {
    // Skip rate limit for OPTIONS preflight
    return req.method === 'OPTIONS'
  },
})

// Stricter rate limiter for sensitive endpoints (e.g., auth, if added later)
export const strictRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // max 5 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => getClientIP(req),
  handler: (req: Request, res: Response) => {
    const ip = getClientIP(req)
    logSecurityEvent({
      type: 'RATE_LIMIT_EXCEEDED',
      ip,
      path: req.path,
      method: req.method,
      details: 'Strict rate limit exceeded',
    })
    res.status(429).json({
      error: 'Demasiados intentos. Intenta de nuevo en 15 minutos.',
    })
  },
})
