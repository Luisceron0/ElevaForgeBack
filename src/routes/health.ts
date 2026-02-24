/**
 * Health Check Route
 *
 * OWASP A01 — Only GET allowed
 */

import { Router, Request, Response } from 'express'

const router = Router()

router.get('/', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'elevaforge-backend',
  })
})

// Block all non-GET methods
router.all('/', (_req: Request, res: Response) => {
  res.setHeader('Allow', 'GET')
  return res.status(405).json({ error: 'Method Not Allowed' })
})

export { router as healthRouter }
