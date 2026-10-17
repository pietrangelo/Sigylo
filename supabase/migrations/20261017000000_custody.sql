-- Sigylo custody: blind storage for sealed envelopes.
--
-- The database holds only opaque ciphertext, random ids, a burn flag, an
-- optional SHA-256 revocation digest and an expiry. No keys, no plaintext,
-- no account, no IP address, no creation time.
--
-- The relay (Cloudflare Worker via Hyperdrive) connects as `sigylo_relay`,
-- which can do exactly one thing: call the functions below. It cannot read
-- the tables, so a leaked relay credential cannot dump or enumerate secrets;
-- it can only open ids it already knows. Burn-after-reading and request
-- answering are single atomic statements, safe under concurrent reads.
-- The database clock (now()) is the only clock that decides expiry.

create schema if not exists custody;

create table custody.deposits (
    id                 bytea       primary key check (octet_length(id) = 16),
    payload            bytea       not null check (octet_length(payload) between 1 and 73728),
    burn_after_reading boolean     not null,
    revocation_digest  bytea       check (revocation_digest is null or octet_length(revocation_digest) = 32),
    expires_at         timestamptz not null
);
create index deposits_expires_at on custody.deposits (expires_at);

create table custody.requests (
    id            bytea       primary key check (octet_length(id) = 16),
    recipient_key bytea       not null check (octet_length(recipient_key) = 1216),
    expires_at    timestamptz not null
);
create index requests_expires_at on custody.requests (expires_at);

-- Deny by default: RLS on with no policies, and no table privileges for anyone
-- but the owner. (Supabase does not expose the `custody` schema over PostgREST.)
alter table custody.deposits enable row level security;
alter table custody.requests enable row level security;
alter table custody.deposits force row level security;
alter table custody.requests force row level security;
revoke all on schema custody from public;
revoke all on all tables in schema custody from public;

create function custody.lifetime(p_seconds integer) returns interval
language plpgsql immutable set search_path = '' as $$
begin
    if p_seconds is null or p_seconds < 300 or p_seconds > 604800 then
        raise exception 'lifetime out of range' using errcode = '22023';
    end if;
    return make_interval(secs => p_seconds);
end $$;

create function custody.deposit(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean,
    p_lifetime_seconds integer, p_revocation_digest bytea
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    -- An expired row is gone in every observable way; let its id be reused.
    delete from custody.deposits where id = p_id and expires_at <= now();
    insert into custody.deposits (id, payload, burn_after_reading, revocation_digest, expires_at)
    values (p_id, p_payload, p_burn_after_reading, p_revocation_digest,
            now() + custody.lifetime(p_lifetime_seconds))
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

create function custody.open(p_id bytea)
returns table (payload bytea, burned boolean)
language sql security definer set search_path = '' as $$
    with burned as (
        delete from custody.deposits d
        where d.id = p_id and d.burn_after_reading and d.expires_at > now()
        returning d.payload
    )
    select b.payload, true from burned b
    union all
    select d.payload, false from custody.deposits d
    where d.id = p_id and not d.burn_after_reading and d.expires_at > now();
$$;

create function custody.revoke(p_id bytea, p_revocation_digest bytea) returns boolean
language sql security definer set search_path = '' as $$
    with gone as (
        delete from custody.deposits d
        where d.id = p_id and d.revocation_digest = p_revocation_digest and d.expires_at > now()
        returning 1
    )
    select exists (select 1 from gone);
$$;

create function custody.post_request(p_id bytea, p_recipient_key bytea, p_lifetime_seconds integer)
returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    delete from custody.requests where id = p_id and expires_at <= now();
    insert into custody.requests (id, recipient_key, expires_at)
    values (p_id, p_recipient_key, now() + custody.lifetime(p_lifetime_seconds))
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

create function custody.fetch_request(p_id bytea)
returns table (recipient_key bytea, expires_at bigint)
language sql stable security definer set search_path = '' as $$
    select r.recipient_key, extract(epoch from r.expires_at)::bigint
    from custody.requests r
    where r.id = p_id and r.expires_at > now();
$$;

-- Consume the request and store the answer under its id, atomically.
-- Returns null when there is no live request (never existed, expired, answered).
create function custody.answer_request(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean, p_lifetime_seconds integer
) returns bigint
language plpgsql security definer set search_path = '' as $$
begin
    delete from custody.requests where id = p_id and expires_at > now();
    if not found then
        return null;
    end if;
    return custody.deposit(p_id, p_payload, p_burn_after_reading, p_lifetime_seconds, null);
end $$;

create function custody.purge_expired() returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_deposits bigint;
    v_requests bigint;
begin
    delete from custody.deposits where expires_at <= now();
    get diagnostics v_deposits = row_count;
    delete from custody.requests where expires_at <= now();
    get diagnostics v_requests = row_count;
    return v_deposits + v_requests;
end $$;

-- Functions are executable by PUBLIC by default: take that away first.
revoke execute on all functions in schema custody from public;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'sigylo_relay') then
        -- The operator sets a password and LOGIN when wiring Hyperdrive (see README).
        create role sigylo_relay nologin;
    end if;
end $$;

grant usage on schema custody to sigylo_relay;
grant execute on function
    custody.deposit(bytea, bytea, boolean, integer, bytea),
    custody.open(bytea),
    custody.revoke(bytea, bytea),
    custody.post_request(bytea, bytea, integer),
    custody.fetch_request(bytea),
    custody.answer_request(bytea, bytea, boolean, integer),
    custody.purge_expired()
to sigylo_relay;
