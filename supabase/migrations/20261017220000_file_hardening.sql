-- Sigylo custody: file hardening after the security review.
--
-- * A file whose chunks are not all in expires within ten minutes; its last
--   chunk gives it back the lifetime the sender chose. So nobody can hold the
--   5 GiB chunk budget with uploads they never finish.
-- * custody.put_chunk takes a transaction lock, so concurrent uploads cannot
--   both fit the last room under the budget.
--
-- Additive: the functions keep their signatures, so the live relay keeps
-- working while this runs. Deposits made before it keep their expiry.

alter table custody.deposits
    -- While chunks are missing: the expiry the sender chose, held back.
    add column expires_when_complete timestamptz check (expires_when_complete is null or chunk_count > 0);

create or replace function custody.deposit(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean,
    p_lifetime_seconds integer, p_revocation_digest bytea, p_chunk_count smallint
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz := now() + custody.lifetime(p_lifetime_seconds);
begin
    -- An expired row is gone in every observable way; let its id be reused.
    delete from custody.deposits where id = p_id and expires_at <= now();
    insert into custody.deposits
        (id, payload, burn_after_reading, revocation_digest, expires_at, chunk_count, expires_when_complete)
    values (p_id, p_payload, p_burn_after_reading, p_revocation_digest,
            case when p_chunk_count > 0 then least(v_expires, now() + interval '10 minutes') else v_expires end,
            p_chunk_count,
            case when p_chunk_count > 0 then v_expires end);
    return extract(epoch from v_expires)::bigint;
end $$;

-- Records that chunk p_idx of a file is the R2 object p_object, already
-- stored by the relay. False when the deposit does not take that chunk.
create or replace function custody.put_chunk(p_id bytea, p_idx smallint, p_object bytea, p_size integer) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    -- One chunk at a time, so concurrent uploads cannot both fit the last room.
    perform pg_advisory_xact_lock(7135340241);
    if (select coalesce(sum(c.size), 0) from custody.chunks c) + p_size > 5::bigint * 1024 * 1024 * 1024 then
        raise exception 'chunk storage full' using errcode = '53100';
    end if;
    insert into custody.chunks (deposit_id, idx, object, size)
    select d.id, p_idx, p_object, p_size
    from custody.deposits d
    where d.id = p_id and d.expires_at > now() and d.claim_digest is null and p_idx < d.chunk_count;
    if not found then
        return false;
    end if;
    update custody.deposits d
    set expires_at = d.expires_when_complete, expires_when_complete = null
    where d.id = p_id and d.expires_when_complete is not null and custody.complete(d.id, d.chunk_count);
    return true;
end $$;
