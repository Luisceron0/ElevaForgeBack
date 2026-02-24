/**
 * Supabase Server Client
 *
 * Uses the service role key for server-side operations.
 * NEVER expose this key to the frontend.
 */

import { createClient } from '@supabase/supabase-js'

export function createServerSupabaseClient() {
  const supabaseUrl = process.env.SUPABASE_URL
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY

  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error('Missing Supabase environment variables (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)')
  }

  return createClient(supabaseUrl, serviceRoleKey)
}
