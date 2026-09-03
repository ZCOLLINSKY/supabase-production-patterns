-- LightDeck public-schema lockdown (idempotent, server-only data plane).
--
-- The browser uses Supabase's /auth/v1 OTP endpoint only. All application data
-- and RPC calls pass through LightDeck's authenticated Vercel API, which sends
-- the service-role key in BOTH apikey and Authorization. This migration makes
-- that architecture an enforced database invariant for current and future
-- application-owned objects without changing extension-owned objects.

BEGIN;
SET LOCAL lock_timeout = '5s';

-- Clear Security/Performance Advisor findings that are independent of object
-- grants. The helper function predates this lockdown and inherited a
-- caller-controlled search_path; the team policy was a permissive USING(true)
-- policy created for service_role even though service_role already bypasses RLS.
-- team_members also accumulated duplicate non-unique indexes beside its
-- canonical unique indexes. Refuse the cleanup if those canonical indexes are
-- missing so schema drift can never turn this into an accidental index outage.
DO $$
DECLARE
  required record;
BEGIN
  IF pg_catalog.to_regprocedure('public.update_updated_at()') IS NOT NULL THEN
    EXECUTE 'ALTER FUNCTION public.update_updated_at() SET search_path = pg_catalog, public';
  END IF;

  IF pg_catalog.to_regclass('public.team_members') IS NOT NULL THEN
    FOR required IN
      SELECT *
        FROM (VALUES
          ('team_members_invite_code_key'::text, 'invite_code'::text),
          ('team_members_session_token_key'::text, 'session_token'::text)
        ) AS expected(index_name, column_name)
    LOOP
      IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_constraint constraint_row
          JOIN pg_catalog.pg_index index_row
            ON index_row.indexrelid = constraint_row.conindid
          JOIN pg_catalog.pg_attribute column_row
            ON column_row.attrelid = constraint_row.conrelid
           AND column_row.attname = required.column_name
           AND NOT column_row.attisdropped
         WHERE constraint_row.conrelid = pg_catalog.to_regclass('public.team_members')
           AND constraint_row.conname = required.index_name
           AND constraint_row.contype = 'u'
           AND constraint_row.convalidated
           AND constraint_row.conindid = pg_catalog.to_regclass(
             pg_catalog.format('%I.%I', 'public', required.index_name)
           )
           AND constraint_row.conkey = ARRAY[column_row.attnum]
           AND index_row.indisunique
           AND index_row.indisvalid
           AND index_row.indisready
           AND index_row.indnkeyatts = 1
           AND index_row.indpred IS NULL
           AND index_row.indexprs IS NULL
      ) THEN
        RAISE EXCEPTION 'team_members canonical unique constraint % on % is missing or invalid',
          required.index_name,
          required.column_name;
      END IF;
    END LOOP;

    FOR required IN
      SELECT *
        FROM (VALUES
          ('idx_team_invite'::text, 'invite_code'::text),
          ('team_members_invite_code_idx'::text, 'invite_code'::text),
          ('idx_team_session'::text, 'session_token'::text),
          ('team_members_session_token_idx'::text, 'session_token'::text)
        ) AS expected(index_name, column_name)
    LOOP
      IF pg_catalog.to_regclass(
           pg_catalog.format('%I.%I', 'public', required.index_name)
         ) IS NOT NULL
         AND NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_index index_row
             JOIN pg_catalog.pg_attribute column_row
               ON column_row.attrelid = index_row.indrelid
              AND column_row.attname = required.column_name
              AND NOT column_row.attisdropped
            WHERE index_row.indexrelid = pg_catalog.to_regclass(
                    pg_catalog.format('%I.%I', 'public', required.index_name)
                  )
              AND index_row.indrelid = pg_catalog.to_regclass('public.team_members')
              AND NOT index_row.indisunique
              AND NOT index_row.indisprimary
              AND NOT index_row.indisexclusion
              AND index_row.indisvalid
              AND index_row.indisready
              AND index_row.indnkeyatts = 1
              AND index_row.indnatts = 1
              AND index_row.indkey[0] = column_row.attnum
              AND index_row.indpred IS NULL
              AND index_row.indexprs IS NULL
              AND NOT EXISTS (
                SELECT 1
                  FROM pg_catalog.pg_constraint constraint_row
                 WHERE constraint_row.conindid = index_row.indexrelid
              )
         ) THEN
        RAISE EXCEPTION 'team_members redundant index % is not the expected disposable index on %',
          required.index_name,
          required.column_name;
      END IF;
    END LOOP;

    EXECUTE 'DROP POLICY IF EXISTS "Service role full access" ON public.team_members';
    EXECUTE 'DROP INDEX IF EXISTS public.idx_team_invite';
    EXECUTE 'DROP INDEX IF EXISTS public.team_members_invite_code_idx';
    EXECUTE 'DROP INDEX IF EXISTS public.idx_team_session';
    EXECUTE 'DROP INDEX IF EXISTS public.team_members_session_token_idx';
  END IF;
END;
$$;

-- Automatically protect any future application relation or routine created in
-- public. The trigger is deliberately schema-scoped and skips extension-owned
-- objects; unlike a database-wide function default it cannot alter auth,
-- storage, extensions, or another product's schema.
CREATE OR REPLACE FUNCTION public.lightdeck_enable_rls_on_new_table()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  cmd record;
  target record;
  browser_role text;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
  LOOP
    IF cmd.schema_name IS DISTINCT FROM 'public' OR coalesce(cmd.in_extension, false) THEN
      CONTINUE;
    END IF;

    SELECT n.nspname AS schema_name, c.relname AS object_name, c.relkind
      INTO target
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE cmd.classid = 'pg_class'::regclass
       AND c.oid = cmd.objid
       AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       );

    IF FOUND THEN
      IF target.relkind IN ('r', 'p') THEN
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', target.schema_name, target.object_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', target.schema_name, target.object_name);
      END IF;

      IF target.relkind = 'S' THEN
        EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC', target.schema_name, target.object_name);
        FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
        LOOP
          IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
            EXECUTE format(
              'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I',
              target.schema_name,
              target.object_name,
              browser_role
            );
          END IF;
        END LOOP;
        IF pg_catalog.to_regrole('service_role') IS NOT NULL THEN
          EXECUTE format(
            'GRANT USAGE, SELECT, UPDATE ON SEQUENCE %I.%I TO service_role',
            target.schema_name,
            target.object_name
          );
        END IF;
      ELSE
        EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC', target.schema_name, target.object_name);
        FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
        LOOP
          IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
            EXECUTE format(
              'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I',
              target.schema_name,
              target.object_name,
              browser_role
            );
          END IF;
        END LOOP;
        IF pg_catalog.to_regrole('service_role') IS NOT NULL THEN
          EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO service_role',
            target.schema_name,
            target.object_name
          );
        END IF;
      END IF;
      CONTINUE;
    END IF;

    SELECT
      n.nspname AS schema_name,
      p.proname AS object_name,
      pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments
      INTO target
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE cmd.classid = 'pg_proc'::regclass
       AND p.oid = cmd.objid
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
       );

    IF FOUND THEN
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM PUBLIC',
        target.schema_name,
        target.object_name,
        target.identity_arguments
      );
      FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
      LOOP
        IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
          EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %I',
            target.schema_name,
            target.object_name,
            target.identity_arguments,
            browser_role
          );
        END IF;
      END LOOP;
      IF pg_catalog.to_regrole('service_role') IS NOT NULL THEN
        EXECUTE format(
          'GRANT EXECUTE ON ROUTINE %I.%I(%s) TO service_role',
          target.schema_name,
          target.object_name,
          target.identity_arguments
        );
      END IF;
    END IF;
  END LOOP;
END;
$$;

DROP EVENT TRIGGER IF EXISTS ensure_lightdeck_public_rls;
CREATE EVENT TRIGGER ensure_lightdeck_public_rls
  ON ddl_command_end
  WHEN TAG IN (
    'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'CREATE VIEW',
    'CREATE MATERIALIZED VIEW', 'CREATE FOREIGN TABLE', 'CREATE SEQUENCE',
    'CREATE FUNCTION', 'CREATE PROCEDURE'
  )
  EXECUTE FUNCTION public.lightdeck_enable_rls_on_new_table();

-- Reconcile every current non-extension table, including tables introduced
-- after the older hand-maintained RLS migration.
DO $$
DECLARE
  target record;
BEGIN
  FOR target IN
    SELECT n.nspname AS schema_name, c.relname AS relation_name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       )
  LOOP
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', target.schema_name, target.relation_name);
    EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', target.schema_name, target.relation_name);
  END LOOP;
END;
$$;

-- Browser roles have no direct application-data path. Role lookup is guarded
-- so the migration gives a clear architecture error for a missing service role
-- and remains portable in a database that omits either optional browser role.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

DO $$
DECLARE
  target record;
  browser_role text;
BEGIN
  IF pg_catalog.to_regrole('service_role') IS NULL THEN
    RAISE EXCEPTION 'LightDeck lockdown requires the Supabase service_role role';
  END IF;

  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', browser_role);
    END IF;
  END LOOP;
  GRANT USAGE ON SCHEMA public TO service_role;

  -- TABLES/ALL FUNCTIONS would also mutate extension members installed into
  -- public. Reconcile application-owned relations one at a time instead.
  FOR target IN
    SELECT n.nspname AS schema_name, c.relname AS object_name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       )
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC', target.schema_name, target.object_name);
    FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
      IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
        EXECUTE format(
          'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I',
          target.schema_name,
          target.object_name,
          browser_role
        );
      END IF;
    END LOOP;
    EXECUTE format(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO service_role',
      target.schema_name,
      target.object_name
    );
  END LOOP;

  FOR target IN
    SELECT n.nspname AS schema_name, c.relname AS object_name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'S'
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       )
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC', target.schema_name, target.object_name);
    FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
      IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
        EXECUTE format(
          'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I',
          target.schema_name,
          target.object_name,
          browser_role
        );
      END IF;
    END LOOP;
    EXECUTE format(
      'GRANT USAGE, SELECT, UPDATE ON SEQUENCE %I.%I TO service_role',
      target.schema_name,
      target.object_name
    );
  END LOOP;

  FOR target IN
    SELECT
      n.nspname AS schema_name,
      p.proname AS object_name,
      pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public'
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
       )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM PUBLIC',
      target.schema_name,
      target.object_name,
      target.identity_arguments
    );
    FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
      IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
        EXECUTE format(
          'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %I',
          target.schema_name,
          target.object_name,
          target.identity_arguments,
          browser_role
        );
      END IF;
    END LOOP;
    EXECUTE format(
      'GRANT EXECUTE ON ROUTINE %I.%I(%s) TO service_role',
      target.schema_name,
      target.object_name,
      target.identity_arguments
    );
  END LOOP;
END;
$$;

-- Keep Supabase's schema-scoped role defaults least-privileged for future
-- public objects. PostgreSQL's built-in PUBLIC function grant cannot be
-- revoked per schema; the event trigger above removes it on each new public
-- routine without changing the creator's defaults in unrelated schemas.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;

DO $$
DECLARE
  browser_role text;
BEGIN
  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    IF pg_catalog.to_regrole(browser_role) IS NOT NULL THEN
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', browser_role);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', browser_role);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM %I', browser_role);
    END IF;
  END LOOP;

  IF pg_catalog.to_regrole('service_role') IS NULL THEN
    RAISE EXCEPTION 'LightDeck lockdown requires the Supabase service_role role';
  END IF;
  ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO service_role;
  ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO service_role;
  ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO service_role;
END;
$$;

-- Prove the public-only future-object guard with a routine created after the
-- event trigger. CREATE OR REPLACE would retain old ACLs, so always recreate
-- the probe and remove it after verification.
DROP FUNCTION IF EXISTS public.lightdeck_lockdown_future_function_probe();
CREATE FUNCTION public.lightdeck_lockdown_future_function_probe()
RETURNS boolean
LANGUAGE sql
SET search_path = pg_catalog
AS $$ SELECT true $$;

DO $$
DECLARE
  probe_oid oid;
  browser_oid oid;
  browser_role text;
BEGIN
  SELECT p.oid INTO STRICT probe_oid
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.proname = 'lightdeck_lockdown_future_function_probe'
     AND p.pronargs = 0;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))
      ) acl
     WHERE p.oid = probe_oid
       AND acl.grantee = 0
       AND acl.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'Future-object verification failed: a newly created public function is executable by PUBLIC';
  END IF;

  FOREACH browser_role IN ARRAY ARRAY['anon', 'authenticated']
  LOOP
    browser_oid := pg_catalog.to_regrole(browser_role);
    IF browser_oid IS NOT NULL
       AND pg_catalog.has_function_privilege(browser_oid, probe_oid, 'EXECUTE') THEN
      RAISE EXCEPTION 'Future-object verification failed: role % can execute a newly created public function', browser_role;
    END IF;
  END LOOP;

  IF NOT pg_catalog.has_function_privilege(
    pg_catalog.to_regrole('service_role'),
    probe_oid,
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'Future-object verification failed: service_role cannot execute a newly created public function';
  END IF;
END;
$$;

DROP FUNCTION public.lightdeck_lockdown_future_function_probe();

-- Fail the transaction instead of leaving a deceptively partial lockdown.
DO $$
DECLARE
  anon_oid oid := pg_catalog.to_regrole('anon');
  authenticated_oid oid := pg_catalog.to_regrole('authenticated');
BEGIN
  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       )
  ) THEN
    RAISE EXCEPTION 'RLS lockdown verification failed: at least one public application table is not enabled and forced';
  END IF;

  IF (anon_oid IS NOT NULL AND pg_catalog.has_schema_privilege(anon_oid, 'public', 'USAGE'))
     OR (authenticated_oid IS NOT NULL AND pg_catalog.has_schema_privilege(authenticated_oid, 'public', 'USAGE')) THEN
    RAISE EXCEPTION 'Public-schema lockdown verification failed: a browser role retains schema usage';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       )
       AND (
         (anon_oid IS NOT NULL AND (
           pg_catalog.has_table_privilege(anon_oid, c.oid, 'SELECT')
           OR pg_catalog.has_table_privilege(anon_oid, c.oid, 'INSERT')
           OR pg_catalog.has_table_privilege(anon_oid, c.oid, 'UPDATE')
           OR pg_catalog.has_table_privilege(anon_oid, c.oid, 'DELETE')
         ))
         OR (authenticated_oid IS NOT NULL AND (
           pg_catalog.has_table_privilege(authenticated_oid, c.oid, 'SELECT')
           OR pg_catalog.has_table_privilege(authenticated_oid, c.oid, 'INSERT')
           OR pg_catalog.has_table_privilege(authenticated_oid, c.oid, 'UPDATE')
           OR pg_catalog.has_table_privilege(authenticated_oid, c.oid, 'DELETE')
         ))
       )
  ) THEN
    RAISE EXCEPTION 'Public-schema lockdown verification failed: a browser role retains application-relation privileges';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'S'
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
       )
       AND (
         (anon_oid IS NOT NULL AND pg_catalog.has_sequence_privilege(anon_oid, c.oid, 'USAGE'))
         OR (authenticated_oid IS NOT NULL AND pg_catalog.has_sequence_privilege(authenticated_oid, c.oid, 'USAGE'))
       )
  ) THEN
    RAISE EXCEPTION 'Public-schema lockdown verification failed: a browser role retains application-sequence privileges';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public'
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
       )
       AND (
         (anon_oid IS NOT NULL AND pg_catalog.has_function_privilege(anon_oid, p.oid, 'EXECUTE'))
         OR (authenticated_oid IS NOT NULL AND pg_catalog.has_function_privilege(authenticated_oid, p.oid, 'EXECUTE'))
       )
  ) THEN
    RAISE EXCEPTION 'RLS lockdown verification failed: an application function remains executable by a browser role';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))
      ) acl
     WHERE n.nspname = 'public'
       AND acl.grantee = 0
       AND acl.privilege_type = 'EXECUTE'
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
       )
  ) THEN
    RAISE EXCEPTION 'RLS lockdown verification failed: an application function remains executable by PUBLIC';
  END IF;
END;
$$;

-- Human-readable success row for the SQL Editor result pane. The DO block above
-- already fails closed; these values make a completed run easy to verify.
SELECT
  count(*)::integer AS application_tables,
  coalesce(bool_and(c.relrowsecurity AND c.relforcerowsecurity), true) AS all_tables_rls_forced,
  (
    SELECT count(*)::integer
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
     WHERE pn.nspname = 'public'
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
       )
       AND (
         (pg_catalog.to_regrole('anon') IS NOT NULL
           AND pg_catalog.has_function_privilege(pg_catalog.to_regrole('anon'), p.oid, 'EXECUTE'))
         OR (pg_catalog.to_regrole('authenticated') IS NOT NULL
           AND pg_catalog.has_function_privilege(pg_catalog.to_regrole('authenticated'), p.oid, 'EXECUTE'))
       )
  ) AS browser_executable_functions
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p')
  AND NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_depend d
     WHERE d.classid = 'pg_class'::regclass
       AND d.objid = c.oid
       AND d.deptype = 'e'
  );

COMMIT;
