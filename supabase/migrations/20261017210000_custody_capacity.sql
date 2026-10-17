-- Sigylo custody: a ceiling on what the custody may hold.
--
-- The free Supabase database stops at 500 MB and then turns read-only: no
-- secret could be opened or sealed until someone freed space by hand. A
-- flood of deposits (30 a minute per address, from many addresses) reaches
-- that in hours. The custody now refuses anything new past its own ceiling,
-- well below the database limit, with SQLSTATE 53100 (disk_full), which the
-- relay reports as CustodyFull. Opening, revoking and purging keep working,
-- and room comes back as secrets are burned, revoked or expire.
--
-- The ceiling counts the stored bytes themselves, not the files on disk,
-- which never shrink after a delete: a full custody that empties must accept
-- new secrets again. Expired rows still on disk count until they go; when
-- the ceiling is reached they are purged on the spot before refusing.
--
-- Compatible with the relay already deployed: it reports the refusal as
-- VaultUnavailable until the new relay is out.

-- PL/pgSQL, not SQL: a SQL function would be inlined into the plans the
-- relay's connections cache, and a new ceiling would not reach them.
create function custody.capacity_bytes() returns bigint
language plpgsql stable set search_path = '' as $$
begin
    return 300 * 1024 * 1024;
end $$;

create function custody.used_bytes() returns bigint
language sql stable set search_path = '' as $$
    select coalesce((select sum(octet_length(payload)) from custody.deposits), 0)
         + coalesce((select sum(octet_length(recipient_key)) from custody.requests), 0)
$$;

create function custody.ensure_room(p_bytes bigint) returns void
language plpgsql set search_path = '' as $$
begin
    if custody.used_bytes() + p_bytes <= custody.capacity_bytes() then
        return;
    end if;
    perform custody.purge_expired();
    if custody.used_bytes() + p_bytes > custody.capacity_bytes() then
        raise exception 'custody full' using errcode = '53100';
    end if;
end $$;

create or replace function custody.deposit(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean,
    p_lifetime_seconds integer, p_revocation_digest bytea
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    perform custody.ensure_room(octet_length(p_payload));
    -- An expired row is gone in every observable way; let its id be reused.
    delete from custody.deposits where id = p_id and expires_at <= now();
    insert into custody.deposits (id, payload, burn_after_reading, revocation_digest, expires_at)
    values (p_id, p_payload, p_burn_after_reading, p_revocation_digest,
            now() + custody.lifetime(p_lifetime_seconds))
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

create or replace function custody.post_request(
    p_id bytea, p_inbox_id bytea, p_recipient_key bytea, p_lifetime_seconds integer
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    if p_inbox_id is null then
        raise exception 'inbox id required' using errcode = '22023';
    end if;
    perform custody.ensure_room(octet_length(p_recipient_key));
    delete from custody.requests where id = p_id and expires_at <= now();
    insert into custody.requests (id, inbox_id, recipient_key, expires_at)
    values (p_id, p_inbox_id, p_recipient_key, now() + custody.lifetime(p_lifetime_seconds))
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

-- The deployed relay's three-argument form, kept until it is retired.
create or replace function custody.post_request(p_id bytea, p_recipient_key bytea, p_lifetime_seconds integer)
returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    perform custody.ensure_room(octet_length(p_recipient_key));
    delete from custody.requests where id = p_id and expires_at <= now();
    insert into custody.requests (id, recipient_key, expires_at)
    values (p_id, p_recipient_key, now() + custody.lifetime(p_lifetime_seconds))
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

-- Helpers run only inside the functions above, as their owner.
revoke execute on function custody.capacity_bytes(), custody.used_bytes(), custody.ensure_room(bigint) from public;
