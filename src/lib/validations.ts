/**
 * Zod Validation Schemas
 *
 * OWASP A03:2025 — Injection Prevention
 * Server-side validation with strict schemas.
 */

import { z } from 'zod'

export const leadSchema = z.object({
  nombre: z
    .string()
    .min(2, 'El nombre debe tener al menos 2 caracteres')
    .max(100, 'El nombre no puede exceder 100 caracteres')
    .regex(/^[a-zA-ZÀ-ÿ\s.'-]+$/, 'El nombre contiene caracteres no válidos'),
  email: z
    .string()
    .email('Email inválido')
    .max(254, 'El email es demasiado largo')
    .transform((v) => v.toLowerCase().trim()),
  empresa: z
    .string()
    .max(100, 'El nombre de empresa no puede exceder 100 caracteres')
    .optional()
    .nullable(),
  telefono: z
    .string()
    .max(32, 'El teléfono no puede exceder 32 caracteres')
    .optional()
    .nullable(),
  mensaje: z
    .string()
    .max(500, 'El mensaje no puede exceder 500 caracteres')
    .optional()
    .nullable(),
  servicio: z
    .string()
    .max(64, 'El servicio no puede exceder 64 caracteres')
    .optional()
    .nullable(),
  presupuesto: z
    .string()
    .max(64, 'El presupuesto no puede exceder 64 caracteres')
    .optional()
    .nullable(),
  contacto_pref: z
    .string()
    .max(16, 'La preferencia no puede exceder 16 caracteres')
    .optional()
    .nullable(),
  utm_source: z
    .string()
    .max(100)
    .optional()
    .nullable(),
  utm_medium: z
    .string()
    .max(100)
    .optional()
    .nullable(),
  utm_campaign: z
    .string()
    .max(100)
    .optional()
    .nullable(),
  consent: z.boolean().optional(),
})

export type LeadInput = z.infer<typeof leadSchema>
