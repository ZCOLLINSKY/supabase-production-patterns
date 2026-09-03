-- ============================================================================
-- LightDeck · P0 RLS LOCK-DOWN: enable Row-Level Security on every PII / business
--             table. Generated 2026-06-19. IDEMPOTENT · SAFE · NON-BREAKING.
-- ----------------------------------------------------------------------------
-- WHY THIS IS SAFE (read before running):
--   The LightDeck server authenticates EVERY Supabase call with
--   SUPABASE_SERVICE_ROLE_KEY (lib/api-shared.js: supabaseInsert/Patch/Get/List/
--   Query/Rpc). The service_role Postgres role has the BYPASSRLS attribute, so it
--   IGNORES Row-Level Security entirely. Therefore:
--
--     * Enabling RLS here does NOT break a single server query. /api/* keeps
--       working exactly as today (proposals, invoices, accounts, sessions, etc.).
--     * What it DOES change: a direct caller using the ANON or AUTHENTICATED key
--       (i.e. anyone who has your public project URL + anon key) can no longer
--       read/write these tables. Today there are ZERO policies, which with RLS
--       *disabled* means the tables are wide open to the anon role via PostgREST.
--       With RLS *enabled and no permissive policy*, the default is DENY: anon
--       sees zero rows and cannot write.
--
--   This is the "lock the front door" fix: ENABLE RLS, add NO anon/authenticated
--   policy. The app (service_role) keeps its keys; the public loses its skeleton key.
--
--   The "public proposal view by token" path is NOT affected: the client browser
--   never reads Supabase directly. It calls GET /api/proposals?token=..., which
--   runs server-side on service_role and bypasses RLS. The token is the app-layer
--   access control, not RLS.
--
--   FORCE: ALTER TABLE ... FORCE ROW LEVEL SECURITY makes RLS also apply to the
--   table owner role (postgres): defense in depth. service_role's BYPASSRLS still
--   wins, so the app is unaffected; FORCE only tightens the owner.
--
--   IDEMPOTENT: ENABLE/FORCE ROW LEVEL SECURITY are no-ops if already set, so this
--   is safe to re-run. Tables already RLS-enabled (sms_log, outreach_log,
--   outreach_sequences, ai_usage, proposal_outcomes) are simply re-affirmed.
--
--   support_tickets is written by api/support.js but has no CREATE migration yet,
--   so it is guarded with IF EXISTS and will not error whether or not it exists.
--
-- RUN THIS IN: the Supabase SQL editor for the PRODUCTION project, once.
-- REVERSIBLE: ALTER TABLE public.<t> DISABLE ROW LEVEL SECURITY;  (and NO FORCE)
--
-- BEFORE YOU RUN (checklist):
--   1. Confirm you are in the PRODUCTION project SQL editor (per memory: project
--      <project-ref>). Sanity check first:
--        select tablename from pg_tables where schemaname='public' order by 1;
--   2. Confirm Vercel has SUPABASE_SERVICE_ROLE_KEY set (the API reads it). If the
--      server were on the anon key this would lock it out: it is not.
--   3. Confirm no OTHER surface reads this DB with the anon key (a static site,
--      Retool/Metabase, etc.). None is known to exist in this repo.
--   4. Take a Supabase backup (Database -> Backups) as cheap insurance.
--   5. Run in one shot, then run the VERIFY query at the bottom (all rowsecurity=true).
--   6. Smoke test: open a real proposal share link + view an invoice (still works,
--      service_role bypasses RLS).
--   7. (Recommended) Prove the front door is locked: from a terminal,
--        curl "$SUPABASE_URL/rest/v1/accounts?select=*" -H "apikey: <ANON_KEY>"
--      Before: returns rows. After: returns []  (RLS on, no anon policy = 0 rows).
-- ============================================================================

-- ── Account / auth / session (highest-value PII: emails, tokens, login) ──────
ALTER TABLE public.accounts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.accounts       FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.sessions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sessions       FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.magic_links    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.magic_links    FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.team_members   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members   FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.invites        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invites        FORCE  ROW LEVEL SECURITY;

-- ── Client-facing business data (names, addresses, phones, emails, totals) ───
ALTER TABLE public.clients                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clients                 FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.jobs                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jobs                    FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.proposals               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposals               FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.proposal_approvals      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposal_approvals      FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.proposal_followups      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposal_followups      FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.proposal_views          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposal_views          FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.proposal_status_updates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proposal_status_updates FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.proposal_outcomes       ENABLE ROW LEVEL SECURITY;  -- already on; re-affirm
ALTER TABLE public.proposal_outcomes       FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.lightdeck_leads         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lightdeck_leads         FORCE  ROW LEVEL SECURITY;

-- ── Billing / money (invoices carry client PII + Stripe ids) ─────────────────
ALTER TABLE public.invoices             ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices             FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.stripe_events        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.stripe_events        FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.stripe_orphan_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.stripe_orphan_events FORCE  ROW LEVEL SECURITY;

-- ── Outreach / messaging / ops logs (phones, emails, message bodies) ─────────
ALTER TABLE public.sms_log            ENABLE ROW LEVEL SECURITY;  -- already on; re-affirm
ALTER TABLE public.sms_log            FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.outreach_log       ENABLE ROW LEVEL SECURITY;  -- already on; re-affirm
ALTER TABLE public.outreach_log       FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.outreach_sequences ENABLE ROW LEVEL SECURITY;  -- already on; re-affirm
ALTER TABLE public.outreach_sequences FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.failed_emails      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.failed_emails      FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.ai_usage           ENABLE ROW LEVEL SECURITY;  -- already on; re-affirm
ALTER TABLE public.ai_usage           FORCE  ROW LEVEL SECURITY;

-- ── support_tickets: written by api/support.js but has NO create migration.
--    Guard so this block is a no-op if the table doesn't exist yet. ───────────
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_tables
             WHERE schemaname = 'public' AND tablename = 'support_tickets') THEN
    EXECUTE 'ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE public.support_tickets FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- ============================================================================
-- VERIFY (read-only): every row below should show rls_enabled = true.
-- ============================================================================
SELECT c.relname AS table_name,
       c.relrowsecurity  AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM   pg_class c
JOIN   pg_namespace n ON n.oid = c.relnamespace
WHERE  n.nspname = 'public'
  AND  c.relkind = 'r'
ORDER  BY c.relrowsecurity ASC, c.relname;   -- any rls_enabled=false floats to top
