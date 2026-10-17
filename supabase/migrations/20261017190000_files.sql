-- Sigylo custody: files sealed in chunks.
--
-- A file is a deposit whose payload is the file's sealed manifest, plus up
-- to 10 chunks of opaque ciphertext (1 MiB + 16 bytes at most each). The
-- chunks themselves live in Cloudflare R2, never in this database: for each
-- one, custody.chunks keeps only the random name of its R2 object and its
-- size. The relay still sees only random ids and ciphertext.
--
-- * A file deposit cannot be opened until all its chunks are in. Chunks are
--   written once, and only while the deposit has not been opened.
-- * Opening a burn-after-reading file claims it instead of deleting it: the
--   deposit keeps the SHA-256 of a claim token that only the opener received,
--   can no longer be opened, and expires within an hour at most. Each chunk is
--   handed out at most once, against the claim, and deleted as it goes; the
--   deposit goes with its last chunk.
-- * Deleting a deposit (burn, revocation, expiry, purge) deletes its chunks,
--   and every chunk that goes leaves its object name in custody.garbage,
--   where the relay finds the R2 objects to delete.
-- * All chunks together may not exceed 5 GiB, half of R2's free 10 GB.
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
    object     bytea    not null unique check (octet_length(object) = 16),
    size       integer  not null check (size between 1 and 1048592),
    primary key (deposit_id, idx)
);

-- R2 objects whose chunk is gone; the relay deletes them and then forgets them.
create table custody.garbage (
    object bytea primary key check (octet_length(object) = 16)
);

alter table custody.chunks enable row level security;
alter table custody.chunks force row level security;
alter table custody.garbage enable row level security;
alter table custody.garbage force row level security;
revoke all on custody.chunks, custody.garbage from public;

-- Fires for every way a chunk goes, cascades from its deposit included.
create function custody.chunk_gone() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
    insert into custody.garbage (object) values (old.object) on conflict do nothing;
    return null;
end $$;

create trigger chunk_gone after delete on custody.chunks
    for each row execute function custody.chunk_gone();

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

-- Records that chunk p_idx of a file is the R2 object p_object, already
-- stored by the relay. False when the deposit does not take that chunk.
create function custody.put_chunk(p_id bytea, p_idx smallint, p_object bytea, p_size integer) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    if (select coalesce(sum(c.size), 0) from custody.chunks c) + p_size > 5::bigint * 1024 * 1024 * 1024 then
        raise exception 'chunk storage full' using errcode = '53100';
    end if;
    insert into custody.chunks (deposit_id, idx, object, size)
    select d.id, p_idx, p_object, p_size
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

-- The R2 object of one chunk, and whether handing it out burned it.
create function custody.open_chunk(p_id bytea, p_idx smallint, p_claim_digest bytea)
returns table (object bytea, burned boolean)
language plpgsql security definer set search_path = '' as $$
declare
    v_burn boolean;
    v_object bytea;
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
        return;
    end if;
    if not v_burn then
        return query select c.object, false from custody.chunks c where c.deposit_id = p_id and c.idx = p_idx;
        return;
    end if;
    delete from custody.chunks c where c.deposit_id = p_id and c.idx = p_idx returning c.object into v_object;
    if not exists (select 1 from custody.chunks c where c.deposit_id = p_id) then
        delete from custody.deposits d where d.id = p_id;
    end if;
    if v_object is not null then
        return query select v_object, true;
    end if;
end $$;

create function custody.garbage(p_limit integer) returns setof bytea
language sql security definer set search_path = '' as $$
    select g.object from custody.garbage g limit least(greatest(p_limit, 0), 1000);
$$;

create function custody.forget_garbage(p_objects bytea[]) returns void
language sql security definer set search_path = '' as $$
    delete from custody.garbage g where g.object = any (p_objects);
$$;

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
    custody.put_chunk(bytea, smallint, bytea, integer),
    custody.open(bytea, bytea),
    custody.open_chunk(bytea, smallint, bytea),
    custody.garbage(integer),
    custody.forget_garbage(bytea[]),
    custody.answer_request(bytea, bytea, boolean, integer, smallint)
to sigylo_relay;
