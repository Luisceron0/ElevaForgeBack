/**
 * Leads API Route
 *
 * OWASP protections:
 * - A01: CSRF via Origin validation
 * - A03: Injection via Zod validation + sanitization
 * - A04: Insecure Design via rate limiting (applied in index.ts)
 * - A05: Security Misconfiguration via Content-Type validation
 * - A06: Honeypot for bot detection
 * - A09: Secure logging (no PII)
 * - A10: Body size limit (applied in index.ts)
 */

import { Router, Request, Response } from 'express'
import { createServerSupabaseClient } from '../lib/supabase.js'
import { leadSchema } from '../lib/validations.js'
import { validateOrigin } from '../lib/security/csrf.js'
import { logSecurityEvent } from '../lib/security/logger.js'
import { getClientIP } from '../middleware/security.js'

const router = Router()

/** Strip control characters and HTML-like chars (A03 — Injection) */
function sanitize(value: string): string {
  return value.replace(/[\u0000-\u001F\u007F<>&"']/g, '').trim()
}

router.post('/', async (req: Request, res: Response) => {
  const ip = getClientIP(req)
  const path = '/api/leads'

  try {
    // ── A01: CSRF Protection via Origin header validation ──
    const csrf = validateOrigin(req)
    if (!csrf.valid) {
      logSecurityEvent({
        type: 'CSRF_VIOLATION',
        ip,
        path,
        method: 'POST',
        details: csrf.reason,
      })
      return res.status(403).json({ error: 'Solicitud no autorizada' })
    }

    // ── A05: Validate Content-Type ──
    const contentType = req.headers['content-type']
    if (!contentType?.includes('application/json')) {
      logSecurityEvent({
        type: 'INVALID_CONTENT_TYPE',
        ip,
        path,
        method: 'POST',
      })
      return res.status(415).json({ error: 'Content-Type debe ser application/json' })
    }

    // ── A06: Honeypot — anti-bot invisible field ──
    const rawBody = req.body as Record<string, unknown>
    if (rawBody._hp) {
      logSecurityEvent({
        type: 'HONEYPOT_TRIGGERED',
        ip,
        path,
        method: 'POST',
      })
      // Silently accept to avoid alerting bot
      return res.status(201).json({
        success: true,
        message: 'Lead registrado correctamente',
      })
    }

    // Remove honeypot field before validation
    const { _hp: _honeypot, ...formData } = rawBody

    // ── A03: Server-side validation (Injection prevention) ──
    const parsed = leadSchema.safeParse(formData)
    if (!parsed.success) {
      logSecurityEvent({
        type: 'VALIDATION_FAILURE',
        ip,
        path,
        method: 'POST',
      })
      return res.status(400).json({
        error: 'Datos inválidos',
        details: parsed.error.flatten(),
      })
    }

    // ── A03: Sanitize all string fields ──
    const sanitizedData = {
      nombre: sanitize(parsed.data.nombre),
      email: sanitize(parsed.data.email).toLowerCase(),
      empresa: parsed.data.empresa ? sanitize(parsed.data.empresa) : null,
      telefono: parsed.data.telefono ? sanitize(parsed.data.telefono) : null,
      mensaje: parsed.data.mensaje ? sanitize(parsed.data.mensaje).slice(0, 500) : null,
      servicio: parsed.data.servicio ? sanitize(parsed.data.servicio) : null,
      presupuesto: parsed.data.presupuesto ? sanitize(parsed.data.presupuesto) : null,
      contacto_pref: parsed.data.contacto_pref ? sanitize(parsed.data.contacto_pref) : null,
      utm_source: parsed.data.utm_source ? sanitize(parsed.data.utm_source) : null,
      utm_medium: parsed.data.utm_medium ? sanitize(parsed.data.utm_medium) : null,
      utm_campaign: parsed.data.utm_campaign ? sanitize(parsed.data.utm_campaign) : null,
      origen: 'landing_elevaforge',
    }

    // ── Insert into Supabase ──
    const supabase = createServerSupabaseClient()
    const { error } = await supabase.from('leads').insert(sanitizedData)

    if (error) {
      throw error
    }

    return res.status(201).json({
      success: true,
      message: 'Lead registrado correctamente',
    })
  } catch (err) {
    // ── A09: Log securely — never expose internals ──
    logSecurityEvent({
      type: 'UNHANDLED_ERROR',
      ip,
      path,
      method: 'POST',
      details: 'DB or runtime error',
    })
    if (process.env.NODE_ENV === 'development') {
      console.error('Error al guardar lead:', err)
    }
    return res.status(500).json({ error: 'Error interno del servidor' })
  }
})

// ── A01: Deny by default — block all non-POST methods ──
router.all('/', (_req: Request, res: Response) => {
  res.setHeader('Allow', 'POST')
  return res.status(405).json({ error: 'Method Not Allowed' })
})

export { router as leadsRouter }
