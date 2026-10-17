-- Sigylo custody: files sealed in chunks.
--
-- A file is a deposit whose payload is the file's sealed manifest, plus up
-- to 10 chunks of opaque ciphertext (1 MiB + 16 bytes at most each) in
-- custody.chunks. The relay still sees only random ids and ciphertext.
--
-- * A file deposit cannot be opened until all its chunks are in. Chunks are
--   written once, and only while the deposit has not been opened.
-- * Opening a burn-after-reading file claims it instead of deleting it: the
--   deposit keeps the SHA-256 of a claim token that only the opener received,
--   can no longer be opened, and expires within an hour at most. Each chunk is
--   handed out at most once, against the claim, and deleted as it goes; the
--   deposit goes with its last chunk.
-- * Deleting a deposit (burn, revocation, expiry, purge) deletes its chunks.
-- * All chunks together may not exceed 256 MiB, which keeps the Supabase
--   free plan (500 MB) safe from filling up.
--
-- Additive on purpose: the functions of the first migration keep their
-- signatures, so the relay that is live while this runs keeps working. The
-- new relay calls the new overloads.

alter table custody.deposits
    add column chunk_count  smallint not null default 0 check (chunk_count between 0 and 10),
    add column claim_digest bytea    check (claim_digest is null or octet_length(claim_digest) = 32);

create table custody.chunks (
    deposit_id bytea    not null references custody.deposits (id) on delete cascade,
    idx        smallint not null check (idx between 0 and 9),
    ciphertext bytea    not null check (octet_length(ciphertext) between 1 and 1048592),
    primary key (deposit_id, idx)
);

alter table custody.chunks enable row level security;
alter table custody.chunks force row level security;
revoke all on custody.chunks from public;

-- Whether every chunk of a deposit is in (a text deposit has none to wait for).
create function custody.complete(p_id bytea, p_chunk_count smallint) returns boolean
language sql stable set search_path = '' as $$
    select (select count(*) from custody.chunks c where c.deposit_id = p_id) = p_chunk_count;
$$;

create function custody.deposit(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean,
    p_lifetime_seconds integer, p_revocation_digest bytea, p_chunk_count smallint
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    -- An expired row is gone in every observable way; let its id be reused.
    delete from custody.deposits where id = p_id and expires_at <= now();
    insert into custody.deposits (id, payload, burn_after_reading, revocation_digest, expires_at, chunk_count)
    values (p_id, p_payload, p_burn_after_reading, p_revocation_digest,
            now() + custody.lifetime(p_lifetime_seconds), p_chunk_count)
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

create function custody.put_chunk(p_id bytea, p_idx smallint, p_ciphertext bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    if (select coalesce(sum(octet_length(c.ciphertext)), 0) from custody.chunks c)
        + octet_length(p_ciphertext) > 256 * 1024 * 1024 then
        raise exception 'chunk storage full' using errcode = '53100';
    end if;
    insert into custody.chunks (deposit_id, idx, ciphertext)
    select d.id, p_idx, p_ciphertext
    from custody.deposits d
    where d.id = p_id and d.expires_at > now() and d.claim_digest is null and p_idx < d.chunk_count;
    return found;
end $$;

-- The relay draws a claim token for every open and passes its digest; only a
-- burn-after-reading file keeps it.
create function custody.open(p_id bytea, p_claim_digest bytea)
returns table (payload bytea, burned boolean, chunk_count smallint)
language sql security definer set search_path = '' as $$
    with burned as (
        delete from custody.deposits d
        where d.id = p_id and d.burn_after_reading and d.chunk_count = 0 and d.expires_at > now()
        returning d.payload, d.chunk_count
    ), claimed as (
        update custody.deposits d
        set claim_digest = p_claim_digest, expires_at = least(d.expires_at, now() + interval '1 hour')
        where d.id = p_id and d.burn_after_reading and d.chunk_count > 0 and d.claim_digest is null
          and d.expires_at > now() and octet_length(p_claim_digest) = 32
          and custody.complete(d.id, d.chunk_count)
        returning d.payload, d.chunk_count
    )
    select b.payload, true, b.chunk_count from burned b
    union all
    select c.payload, true, c.chunk_count from claimed c
    union all
    select d.payload, false, d.chunk_count from custody.deposits d
    where d.id = p_id and not d.burn_after_reading and d.expires_at > now()
      and custody.complete(d.id, d.chunk_count);
$$;

create function custody.open_chunk(p_id bytea, p_idx smallint, p_claim_digest bytea) returns bytea
language plpgsql security definer set search_path = '' as $$
declare
    v_burn boolean;
    v_ciphertext bytea;
begin
    -- The row lock serializes the chunk reads of one file, so the read that
    -- takes the last chunk sees that it is the last.
    select d.burn_after_reading into v_burn
    from custody.deposits d
    where d.id = p_id and d.expires_at > now()
      and case when d.burn_after_reading then d.claim_digest = p_claim_digest
               else custody.complete(d.id, d.chunk_count) end
    for update;
    if not found then
        return null;
    end if;
    if not v_burn then
        select c.ciphertext into v_ciphertext from custody.chunks c where c.deposit_id = p_id and c.idx = p_idx;
        return v_ciphertext;
    end if;
    delete from custody.chunks c where c.deposit_id = p_id and c.idx = p_idx returning c.ciphertext into v_ciphertext;
    if not exists (select 1 from custody.chunks c where c.deposit_id = p_id) then
        delete from custody.deposits where id = p_id;
    end if;
    return v_ciphertext;
end $$;

create function custody.answer_request(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean, p_lifetime_seconds integer, p_chunk_count smallint
) returns bigint
language plpgsql security definer set search_path = '' as $$
begin
    delete from custody.requests where id = p_id and expires_at > now();
    if not found then
        return null;
    end if;
    return custody.deposit(p_id, p_payload, p_burn_after_reading, p_lifetime_seconds, null, p_chunk_count);
end $$;

-- The first migration's open(bytea) knows nothing of chunks: keep it to text
-- secrets, so it can never burn a file it cannot hand out.
create or replace function custody.open(p_id bytea)
returns table (payload bytea, burned boolean)
language sql security definer set search_path = '' as $$
    with burned as (
        delete from custody.deposits d
        where d.id = p_id and d.burn_after_reading and d.chunk_count = 0 and d.expires_at > now()
        returning d.payload
    )
    select b.payload, true from burned b
    union all
    select d.payload, false from custody.deposits d
    where d.id = p_id and not d.burn_after_reading and d.chunk_count = 0 and d.expires_at > now();
$$;

revoke execute on all functions in schema custody from public;
grant execute on function
    custody.deposit(bytea, bytea, boolean, integer, bytea, smallint),
    custody.put_chunk(bytea, smallint, bytea),
    custody.open(bytea, bytea),
    custody.open_chunk(bytea, smallint, bytea),
    custody.answer_request(bytea, bytea, boolean, integer, smallint)
to sigylo_relay;
