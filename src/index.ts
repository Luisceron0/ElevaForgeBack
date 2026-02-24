/**
 * ElevaForge Backend API
 *
 * Standalone Express server with OWASP Top 10 protections.
 * Designed to be deployed separately from the frontend (Vercel).
 */

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'

import { securityMiddleware } from './middleware/security.js'
import { rateLimiter } from './middleware/rateLimiter.js'
import { leadsRouter } from './routes/leads.js'
import { healthRouter } from './routes/health.js'

const app = express()
const PORT = process.env.PORT || 3001

// ═══════════════════════════════════════════════════════════════
// OWASP A05 — Security Misconfiguration: Helmet sets secure headers
// ═══════════════════════════════════════════════════════════════
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false, // Allow embedding from frontend
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
)

// ═══════════════════════════════════════════════════════════════
// OWASP A01 — CORS: Only allow requests from trusted origins
// ═══════════════════════════════════════════════════════════════
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((o) => o.trim())

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, Postman in dev)
      if (!origin && process.env.NODE_ENV === 'development') {
        return callback(null, true)
      }
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true)
      } else {
        callback(new Error('CORS: Origin not allowed'))
      }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
    credentials: true,
    maxAge: 86400, // Preflight cache 24h
  })
)

// ═══════════════════════════════════════════════════════════════
// OWASP A10 — Body size limit to prevent resource exhaustion
// ═══════════════════════════════════════════════════════════════
app.use(express.json({ limit: '8kb' }))
app.use(express.urlencoded({ extended: false, limit: '8kb' }))

// Custom security middleware (logging, request ID, blocked paths)
app.use(securityMiddleware)

// ═══════════════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════════════

// Health check (no rate limit for monitoring)
app.use('/api/health', healthRouter)

// Leads endpoint with rate limiting
app.use('/api/leads', rateLimiter, leadsRouter)

// ═══════════════════════════════════════════════════════════════
// OWASP A01 — Catch-all 404 for undefined routes
// ═══════════════════════════════════════════════════════════════
app.use((_req, res) => {
  res.status(404).json({ error: 'Not Found' })
})

// ═══════════════════════════════════════════════════════════════
// OWASP A09 — Global error handler (no stack traces in production)
// ═══════════════════════════════════════════════════════════════
app.use(
  (
    err: Error,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error('[ERROR]', err.message)
    if (process.env.NODE_ENV === 'development') {
      console.error(err.stack)
    }
    res.status(500).json({ error: 'Internal Server Error' })
  }
)

// Start server
app.listen(PORT, () => {
  console.log(`🚀 ElevaForge Backend running on port ${PORT}`)
  console.log(`   Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`)
})

export default app
