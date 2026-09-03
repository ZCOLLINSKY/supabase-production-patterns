-- Idempotent proposal publication.
-- A serverless response can be lost after commit; retrying the same confirmed
-- browser action must recover the existing token, not leave two live revisions.

BEGIN;
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.proposals
  ADD COLUMN IF NOT EXISTS create_request_id text;

-- Fail with a useful reconciliation error before creating normalized guards.
-- NULL/blank legacy account ids have always represented the default account.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM public.proposals
     WHERE nullif(btrim(create_request_id), '') IS NOT NULL
     GROUP BY
       coalesce(nullif(btrim(account_id), ''), 'default'),
       nullif(btrim(create_request_id), '')
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'proposals contains duplicate normalized (account_id, create_request_id) rows; reconcile before applying idempotency guard';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM public.proposals
     WHERE nullif(btrim(supersedes_token), '') IS NOT NULL
     GROUP BY
       coalesce(nullif(btrim(account_id), ''), 'default'),
       nullif(btrim(supersedes_token), '')
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'proposals contains parallel revisions for one normalized (account_id, supersedes_token); reconcile before applying revision guard';
  END IF;
END;
$$;

-- Rebuild the first-run index so a partially applied copy cannot retain its
-- older, whitespace-sensitive definition.
DROP INDEX IF EXISTS public.proposals_account_create_request_uniq;
CREATE UNIQUE INDEX proposals_account_create_request_uniq
  ON public.proposals (
    (coalesce(nullif(btrim(account_id), ''), 'default')),
    (nullif(btrim(create_request_id), ''))
  )
  WHERE nullif(btrim(create_request_id), '') IS NOT NULL;

DROP INDEX IF EXISTS public.proposals_account_supersedes_uniq;
CREATE UNIQUE INDEX proposals_account_supersedes_uniq
  ON public.proposals (
    (coalesce(nullif(btrim(account_id), ''), 'default')),
    (nullif(btrim(supersedes_token), ''))
  )
  WHERE nullif(btrim(supersedes_token), '') IS NOT NULL;

CREATE OR REPLACE FUNCTION public.create_proposal_revision(
  p_token text,
  p_proposal_data jsonb,
  p_contractor_email text,
  p_client_email text,
  p_account_id text,
  p_status text,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_selected_package text,
  p_supersedes_token text,
  p_create_request_id text
)
RETURNS TABLE(id bigint, token text, supersedes_token text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  prior public.proposals%ROWTYPE;
  existing_request public.proposals%ROWTYPE;
  existing_child public.proposals%ROWTYPE;
  inserted public.proposals%ROWTYPE;
  v_token text := nullif(btrim(p_token), '');
  v_account_id text := coalesce(nullif(btrim(p_account_id), ''), 'default');
  v_create_request_id text := nullif(btrim(p_create_request_id), '');
  v_supersedes_token text := nullif(btrim(p_supersedes_token), '');
BEGIN
  IF v_token IS NULL
     OR nullif(btrim(p_account_id), '') IS NULL
     OR v_create_request_id IS NULL THEN
    RAISE EXCEPTION 'token, account_id, and create_request_id are required';
  END IF;

  -- The unique index protects every writer. This transaction-scoped lock also
  -- makes two simultaneous invocations with the same browser action wait, so
  -- the loser can return the committed row instead of surfacing unique_violation.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      'lightdeck:proposal-create:' || v_account_id || chr(31) || v_create_request_id,
      0
    )
  );

  -- Transport retry after a successful commit: return the original row before
  -- touching the predecessor again.
  SELECT * INTO existing_request
    FROM public.proposals
   WHERE coalesce(nullif(btrim(proposals.account_id), ''), 'default') = v_account_id
     AND nullif(btrim(proposals.create_request_id), '') = v_create_request_id
   FOR UPDATE;
  IF FOUND THEN
    RETURN QUERY SELECT existing_request.id, existing_request.token, existing_request.supersedes_token;
    RETURN;
  END IF;

  IF v_supersedes_token IS NOT NULL THEN
    -- Different browser actions revising the same predecessor use different
    -- idempotency ids. Serialize that second dimension and reject fan-out.
    PERFORM pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended(
        'lightdeck:proposal-revision:' || v_account_id || chr(31) || v_supersedes_token,
        0
      )
    );

    SELECT * INTO prior
      FROM public.proposals
     WHERE proposals.token = v_supersedes_token
     FOR UPDATE;

    IF NOT FOUND
       OR coalesce(nullif(btrim(prior.account_id), ''), 'default') <> v_account_id THEN
      RAISE EXCEPTION 'superseded proposal not found for account';
    END IF;

    SELECT * INTO existing_child
      FROM public.proposals
     WHERE coalesce(nullif(btrim(proposals.account_id), ''), 'default') = v_account_id
       AND nullif(btrim(proposals.supersedes_token), '') = v_supersedes_token
     LIMIT 1
     FOR UPDATE;
    IF FOUND THEN
      RAISE EXCEPTION 'a proposal revision already exists for this predecessor';
    END IF;

    IF upper(coalesce(prior.status, '')) <> 'ACCEPTED'
       AND nullif(btrim(prior.client_signature), '') IS NULL
       AND prior.accepted_at IS NULL THEN
      UPDATE public.proposals
         SET status = 'REVOKED', expires_at = least(coalesce(expires_at, now()), now())
       WHERE proposals.token = v_supersedes_token;
    END IF;
  END IF;

  INSERT INTO public.proposals (
    token, proposal_data, contractor_email, client_email, account_id, status,
    created_at, expires_at, view_count, last_viewed_at, selected_package,
    supersedes_token, create_request_id
  ) VALUES (
    v_token, p_proposal_data, p_contractor_email, p_client_email, v_account_id,
    p_status, p_created_at, p_expires_at, 0, NULL, p_selected_package,
    v_supersedes_token, v_create_request_id
  )
  RETURNING * INTO inserted;

  RETURN QUERY SELECT inserted.id, inserted.token, inserted.supersedes_token;
END;
$$;

-- CREATE OR REPLACE installs an overload; it does not replace the earlier
-- ten-argument routine. Remove that bypass after the required-id function is live.
DROP FUNCTION IF EXISTS public.create_proposal_revision(text,jsonb,text,text,text,text,timestamptz,timestamptz,text,text);

REVOKE ALL ON FUNCTION public.create_proposal_revision(text,jsonb,text,text,text,text,timestamptz,timestamptz,text,text,text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.create_proposal_revision(text,jsonb,text,text,text,text,timestamptz,timestamptz,text,text,text)
  TO service_role;

COMMENT ON COLUMN public.proposals.create_request_id IS
  'Account-scoped idempotency id for one proposal publication action.';

COMMIT;
