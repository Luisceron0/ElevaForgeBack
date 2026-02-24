# ElevaForge Backend

API backend para ElevaForge. Servidor Express standalone con protecciones OWASP Top 10.

## Requisitos

- Node.js >= 18
- Supabase project con tabla `leads`

## Instalación

```bash
cd backend
npm install
cp .env.example .env
# Edita .env con tus credenciales
```

## Desarrollo

```bash
npm run dev
```

El servidor arranca en `http://localhost:3001`.

## Producción

```bash
npm run build
npm start
```

## Endpoints

| Método | Ruta         | Descripción                |
|--------|--------------|----------------------------|
| GET    | /api/health  | Health check               |
| POST   | /api/leads   | Crear nuevo lead           |

## Protecciones OWASP Top 10

| OWASP ID | Vulnerabilidad                    | Mitigación                                      |
|----------|-----------------------------------|------------------------------------------------|
| A01      | Broken Access Control             | CORS, Origin validation, blocked paths, 405s   |
| A02      | Cryptographic Failures            | HTTPS (deploy), no secrets en código           |
| A03      | Injection                         | Zod validation, input sanitization             |
| A04      | Insecure Design                   | Rate limiting, honeypot                        |
| A05      | Security Misconfiguration         | Helmet, CSP, Content-Type validation           |
| A06      | Vulnerable Components             | Dependencias mínimas, npm audit                |
| A07      | Auth Failures                     | N/A (sin auth público)                         |
| A08      | Software & Data Integrity         | No eval(), no serialización insegura           |
| A09      | Security Logging Failures         | Structured JSON logging, no PII                |
| A10      | SSRF                              | No fetch a URLs externas controladas por user  |

## Variables de Entorno

| Variable                   | Descripción                              |
|----------------------------|------------------------------------------|
| `PORT`                     | Puerto del servidor (default: 3001)      |
| `NODE_ENV`                 | `development` o `production`             |
| `ALLOWED_ORIGINS`          | Origins permitidos (comma-separated)     |
| `SUPABASE_URL`             | URL de tu proyecto Supabase              |
| `SUPABASE_SERVICE_ROLE_KEY`| Service role key (server-side only)     |

## Tabla Supabase `leads`

```sql
CREATE TABLE leads (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nombre TEXT NOT NULL,
  email TEXT NOT NULL,
  empresa TEXT,
  telefono TEXT,
  mensaje TEXT,
  servicio TEXT,
  presupuesto TEXT,
  contacto_pref TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  origen TEXT DEFAULT 'landing_elevaforge',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- RLS: Disable public access (only service role can insert)
ALTER TABLE leads ENABLE ROW LEVEL SECURITY;

-- Policy: Only service role can insert
CREATE POLICY "Service role can insert leads"
  ON leads FOR INSERT
  WITH CHECK (true);
```

## Despliegue

Recomendado: Railway, Render, Fly.io, o cualquier hosting Node.js.

1. Configura las variables de entorno en tu plataforma
2. Asegura que `ALLOWED_ORIGINS` incluya tu dominio de frontend
3. Habilita HTTPS en tu plataforma de hosting
