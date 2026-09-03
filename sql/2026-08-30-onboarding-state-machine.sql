-- Durable, tenant-scoped LightDeck onboarding milestones.
-- Existing accounts derive their milestone from durable history; accounts with
-- no history remain NEW. New accounts advance only through server-owned events.

begin;
set local lock_timeout = '5s';

alter table public.accounts
  add column if not exists onboarding_state text not null default 'NEW',
  add column if not exists onboarding_state_updated_at timestamptz not null default pg_catalog.now(),
  add column if not exists first_job_created_at timestamptz,
  add column if not exists first_proposal_created_at timestamptz,
  add column if not exists activated_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_catalog.pg_constraint
     where conname = 'accounts_onboarding_state_check'
       and conrelid = 'public.accounts'::regclass
  ) then
    alter table public.accounts
      add constraint accounts_onboarding_state_check
      check (onboarding_state in ('NEW', 'FIRST_JOB', 'FIRST_PROPOSAL', 'ACTIVATED'));
  end if;
end $$;

alter table public.jobs
  add column if not exists source_job_id text;

-- Historical job rows predate the browser's stable source id. Give each row a
-- deterministic server id so migration-time and future boot reconciliation can
-- count real jobs without relying on browser storage.
update public.jobs
   set source_job_id = 'legacy_job_' || id::text
 where source_job_id is null;

do $$
begin
  if not exists (
    select 1 from pg_catalog.pg_constraint
     where conname = 'jobs_source_job_id_check'
       and conrelid = 'public.jobs'::regclass
  ) then
    alter table public.jobs
      add constraint jobs_source_job_id_check
      check (
        source_job_id is null or (
          source_job_id = btrim(source_job_id)
          and char_length(source_job_id) between 8 and 200
          and source_job_id ~ '^[A-Za-z0-9_-]+$'
        )
      );
  end if;
  if not exists (
    select 1 from pg_catalog.pg_constraint
     where conname = 'jobs_account_source_job_unique'
       and conrelid = 'public.jobs'::regclass
  ) then
    alter table public.jobs
      add constraint jobs_account_source_job_unique unique (account_id, source_job_id);
  end if;
end $$;

alter table public.proposals
  add column if not exists customer_ready_at timestamptz,
  add column if not exists customer_ready_kind text,
  add column if not exists customer_ready_artifact_sha256 text,
  add column if not exists customer_ready_artifact_bytes bigint,
  add column if not exists customer_ready_artifact_pages integer;

-- Historical public proposal lifecycle states prove a customer-ready share
-- existed. DRAFT is never qualifying. A revoked row qualifies only when durable
-- client interaction or acceptance proves it was public before revocation.
update public.proposals as proposal
   set customer_ready_at = coalesce(proposal.created_at, pg_catalog.now()),
       customer_ready_kind = 'share',
       customer_ready_artifact_sha256 = null,
       customer_ready_artifact_bytes = null,
       customer_ready_artifact_pages = null
 where proposal.customer_ready_at is null
   and (
     upper(coalesce(proposal.status, '')) in (
       'SENT', 'VIEWED', 'REVISION_REQUESTED', 'ACCEPTED', 'DECLINED'
     )
     or (
       upper(coalesce(proposal.status, '')) = 'REVOKED'
       and (proposal.accepted_at is not null or coalesce(proposal.view_count, 0) > 0)
     )
   );

do $$
begin
  if not exists (
    select 1 from pg_catalog.pg_constraint
     where conname = 'proposals_customer_ready_kind_check'
       and conrelid = 'public.proposals'::regclass
  ) then
    alter table public.proposals
      add constraint proposals_customer_ready_kind_check
      check (customer_ready_kind is null or customer_ready_kind in ('share', 'pdf'));
  end if;
  if not exists (
    select 1 from pg_catalog.pg_constraint
     where conname = 'proposals_customer_ready_artifact_check'
       and conrelid = 'public.proposals'::regclass
  ) then
    alter table public.proposals
      add constraint proposals_customer_ready_artifact_check
      check (
        (customer_ready_at is null and customer_ready_kind is null)
        or (
          customer_ready_at is not null
          and customer_ready_kind = 'share'
          and customer_ready_artifact_sha256 is null
          and customer_ready_artifact_bytes is null
          and customer_ready_artifact_pages is null
        )
        or (
          customer_ready_at is not null
          and customer_ready_kind = 'pdf'
          and customer_ready_artifact_sha256 ~ '^[a-f0-9]{64}$'
          and customer_ready_artifact_bytes >= 1024
          and customer_ready_artifact_pages between 1 and 100
        )
      );
  end if;
end $$;

create index if not exists proposals_onboarding_ready_idx
  on public.proposals (account_id, customer_ready_at)
  where customer_ready_at is not null;

-- One-time/lazy-safe history derivation. It only advances, so rerunning this
-- migration cannot regress an achieved milestone. Proposal revisions prove at
-- least one job, but only distinct rows in jobs can satisfy the second-job gate.
with job_history as (
  select account_id,
         count(distinct source_job_id)::integer as job_count,
         min(created_at) as first_job_at
    from public.jobs
   where account_id is not null
     and source_job_id is not null
   group by account_id
), proposal_history as (
  select account_id,
         count(*)::integer as proposal_count,
         min(customer_ready_at) as first_proposal_at
    from public.proposals
   where account_id is not null
     and customer_ready_at is not null
   group by account_id
), derived as (
  select account.id,
         coalesce(job_history.job_count, 0) as job_count,
         coalesce(proposal_history.proposal_count, 0) as proposal_count,
         job_history.first_job_at,
         proposal_history.first_proposal_at,
         case
           when coalesce(proposal_history.proposal_count, 0) > 0
             and coalesce(job_history.job_count, 0) >= 2 then 'ACTIVATED'
           when coalesce(proposal_history.proposal_count, 0) > 0 then 'FIRST_PROPOSAL'
           when coalesce(job_history.job_count, 0) > 0 then 'FIRST_JOB'
           else 'NEW'
         end as target_state
    from public.accounts as account
    left join job_history on job_history.account_id = account.id::text
    left join proposal_history on proposal_history.account_id = account.id::text
)
update public.accounts as account
   set onboarding_state = derived.target_state,
       onboarding_state_updated_at = pg_catalog.now(),
       first_job_created_at = case
         when derived.target_state in ('FIRST_JOB', 'FIRST_PROPOSAL', 'ACTIVATED')
           then coalesce(account.first_job_created_at, derived.first_job_at, derived.first_proposal_at, pg_catalog.now())
         else account.first_job_created_at
       end,
       first_proposal_created_at = case
         when derived.target_state in ('FIRST_PROPOSAL', 'ACTIVATED')
           then coalesce(account.first_proposal_created_at, derived.first_proposal_at, pg_catalog.now())
         else account.first_proposal_created_at
       end,
       activated_at = case
         when derived.target_state = 'ACTIVATED'
           then coalesce(account.activated_at, pg_catalog.now())
         else account.activated_at
       end
  from derived
 where account.id = derived.id
   and array_position(array['NEW','FIRST_JOB','FIRST_PROPOSAL','ACTIVATED'], account.onboarding_state)
     < array_position(array['NEW','FIRST_JOB','FIRST_PROPOSAL','ACTIVATED'], derived.target_state);

create or replace function public.advance_lightdeck_onboarding(
  p_account_id uuid,
  p_target_state text,
  p_event_at timestamptz default pg_catalog.now()
)
returns jsonb
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  target_state text := upper(coalesce(btrim(p_target_state), ''));
  event_at timestamptz := coalesce(p_event_at, pg_catalog.now());
  result jsonb;
begin
  if target_state not in ('NEW', 'FIRST_JOB', 'FIRST_PROPOSAL', 'ACTIVATED') then
    raise exception 'invalid LightDeck onboarding state';
  end if;

  update public.accounts as account
     set onboarding_state = target_state,
         onboarding_state_updated_at = event_at,
         first_job_created_at = case
           when target_state in ('FIRST_JOB', 'FIRST_PROPOSAL', 'ACTIVATED')
             then coalesce(account.first_job_created_at, event_at)
           else account.first_job_created_at
         end,
         first_proposal_created_at = case
           when target_state in ('FIRST_PROPOSAL', 'ACTIVATED')
             then coalesce(account.first_proposal_created_at, event_at)
           else account.first_proposal_created_at
         end,
         activated_at = case
           when target_state = 'ACTIVATED' then coalesce(account.activated_at, event_at)
           else account.activated_at
         end
   where account.id = p_account_id
     and array_position(array['NEW','FIRST_JOB','FIRST_PROPOSAL','ACTIVATED'], account.onboarding_state)
       < array_position(array['NEW','FIRST_JOB','FIRST_PROPOSAL','ACTIVATED'], target_state)
  returning to_jsonb(account) into result;

  if result is null then
    select to_jsonb(account) into result
      from public.accounts as account
     where account.id = p_account_id;
  end if;
  if result is null then raise exception 'LightDeck account not found'; end if;
  return result;
end;
$$;

create or replace function public.record_lightdeck_onboarding_job(
  p_account_id uuid,
  p_source_job_id text,
  p_job jsonb
)
returns jsonb
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  job_record jsonb;
  account_record jsonb;
  current_state text;
  target_state text;
  durable_job_count integer;
  has_customer_ready_proposal boolean;
begin
  if p_account_id is null
     or p_source_job_id is null
     or p_source_job_id <> btrim(p_source_job_id)
     or char_length(p_source_job_id) not between 8 and 200
     or p_source_job_id !~ '^[A-Za-z0-9_-]+$'
     or jsonb_typeof(p_job) is distinct from 'object' then
    raise exception 'invalid LightDeck onboarding job';
  end if;

  insert into public.jobs as job (
    client_name, address, lat, lng, trade, status, total,
    proposal_token, proposal_number, outcome, zip, account_id,
    closed_at, raw_payload, created_at, source_job_id
  ) values (
    left(coalesce(p_job->>'client_name', ''), 160),
    left(coalesce(p_job->>'address', ''), 300),
    nullif(p_job->>'lat', '')::double precision,
    nullif(p_job->>'lng', '')::double precision,
    left(coalesce(p_job->>'trade', ''), 40),
    upper(left(coalesce(nullif(p_job->>'status', ''), 'DRAFT'), 40)),
    round(coalesce(nullif(p_job->>'total', '')::numeric, 0))::integer,
    nullif(left(coalesce(p_job->>'proposal_token', ''), 80), ''),
    left(coalesce(p_job->>'proposal_number', ''), 80),
    nullif(left(coalesce(p_job->>'outcome', ''), 40), ''),
    left(coalesce(p_job->>'zip', ''), 12),
    p_account_id::text,
    nullif(p_job->>'closed_at', '')::timestamptz,
    p_job,
    pg_catalog.now(),
    p_source_job_id
  )
  on conflict (account_id, source_job_id) do update
    set client_name = excluded.client_name,
        address = excluded.address,
        lat = excluded.lat,
        lng = excluded.lng,
        trade = excluded.trade,
        status = excluded.status,
        total = excluded.total,
        proposal_token = coalesce(excluded.proposal_token, job.proposal_token),
        proposal_number = excluded.proposal_number,
        outcome = excluded.outcome,
        zip = excluded.zip,
        closed_at = excluded.closed_at,
        raw_payload = excluded.raw_payload
  returning to_jsonb(job) into job_record;

  select onboarding_state into current_state
    from public.accounts
   where id = p_account_id;
  if current_state is null then raise exception 'LightDeck account not found'; end if;

  select count(distinct source_job_id) into durable_job_count
    from public.jobs
   where account_id = p_account_id::text
     and source_job_id is not null;

  select exists (
    select 1
      from public.proposals
     where account_id = p_account_id::text
       and customer_ready_at is not null
  ) into has_customer_ready_proposal;

  target_state := case
    when has_customer_ready_proposal and durable_job_count >= 2 then 'ACTIVATED'
    when has_customer_ready_proposal then 'FIRST_PROPOSAL'
    else 'FIRST_JOB'
  end;
  account_record := public.advance_lightdeck_onboarding(p_account_id, target_state, pg_catalog.now());
  return jsonb_build_object('job', job_record, 'account', account_record);
end;
$$;

revoke all on function public.advance_lightdeck_onboarding(uuid,text,timestamptz) from public;
revoke all on function public.record_lightdeck_onboarding_job(uuid,text,jsonb) from public;

do $$
declare
  browser_role text;
begin
  if pg_catalog.to_regrole('service_role') is null then
    raise exception 'LightDeck onboarding requires the Supabase service_role role';
  end if;
  foreach browser_role in array array['anon', 'authenticated'] loop
    if pg_catalog.to_regrole(browser_role) is not null then
      execute format(
        'REVOKE ALL ON FUNCTION public.advance_lightdeck_onboarding(uuid,text,timestamptz) FROM %I',
        browser_role
      );
      execute format(
        'REVOKE ALL ON FUNCTION public.record_lightdeck_onboarding_job(uuid,text,jsonb) FROM %I',
        browser_role
      );
    end if;
  end loop;
  grant execute on function public.advance_lightdeck_onboarding(uuid,text,timestamptz) to service_role;
  grant execute on function public.record_lightdeck_onboarding_job(uuid,text,jsonb) to service_role;
end $$;

commit;
