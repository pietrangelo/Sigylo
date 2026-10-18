-- Sigylo custody: a ceiling that counts rows, floors for what is stored, and
-- chunk objects that are never lost track of (second security review).
--
-- * Floors. A payload is at least the smallest envelope a sealer makes
--   (302 bytes); a chunk is a power of two from 256 B to 1 MiB plus its
--   16-byte tag, and every chunk of a file but the last is full (1 048 592 B).
--   One-byte deposits and chunks cost the database a whole row each while
--   the ceiling saw a byte.
-- * The ceiling counts rows, not only bytes: every deposit, request, chunk
--   and garbage row is charged a fixed overhead on top of what it holds.
--   custody.usage keeps the running total, maintained by statement-level
--   triggers, so the ceiling and the 5 GiB chunk budget are O(1) reads
--   instead of full-table sums under the global chunk lock.
-- * The chunk budget counts custody.garbage too: an object still in R2
--   takes room until it is deleted, so revoking in a loop no longer grows R2
--   past the budget.
-- * Garbage waits before it is collected (custody.garbage.not_before): five
--   minutes for a chunk that went, so a burned chunk is never deleted from R2
--   before it was read; fifteen for an upload's reservation.
-- * Uploads reserve first: custody.reserve_chunk refuses at once a chunk the
--   deposit does not take (so nothing is written to R2 for it) and records
--   the object name as garbage before the R2 put, so an interrupted upload
--   leaves nothing unrecorded. custody.record_chunk then turns the
--   reservation into the chunk. A chunk already in is a refusal (false, 404),
--   never a unique violation (409) that told whether a file was opened.
-- * Burning a chunk is a second step (custody.find_chunk, then
--   custody.burn_chunk once R2 delivered it), so an R2 error loses nothing.
-- * custody.revoke_with_objects names the revoked chunks' objects, so the
--   relay deletes them from R2 at once.
--
-- Compatible with the relay deployed while this runs: every function it
-- calls keeps its signature and meaning (put_chunk now answers false for a
-- chunk already in, and garbage() hands out only what is due), and the new
-- relay calls the new functions.

-- Floors. NOT VALID: they hold for every new row without scanning old ones.
alter table custody.deposits
    add constraint deposits_payload_floor check (octet_length(payload) >= 302) not valid;
alter table custody.chunks
    add constraint chunks_size_sealed check (
        size - 16 between 256 and 1048576 and ((size - 16) & (size - 17)) = 0
    ) not valid;

-- An object in the garbage still takes room in R2, and goes only when due.
-- Rows already there predate sizes: count them as full chunks.
alter table custody.garbage
    add column size integer not null default 1048592 check (size between 0 and 1048592),
    add column not_before timestamptz not null default now();
alter table custody.garbage alter column not_before set default now() + interval '5 minutes';

-- What custody holds, kept up to date by the triggers below: one row.
create table custody.usage (
    -- Against custody.capacity_bytes(): stored bytes plus a fixed cost per row.
    used_bytes  bigint not null,
    -- Against the 5 GiB chunk budget: bytes of chunks and garbage objects in R2.
    chunk_bytes bigint not null
);
create unique index usage_single_row on custody.usage ((true));
alter table custody.usage enable row level security;
alter table custody.usage force row level security;
revoke all on custody.usage from public;

-- Fixed cost of one row (tuple header, ids, digests, index entries), so a
-- flood of small rows reaches the ceiling long before the disk fills:
-- deposit 192, request 128, chunk 192, garbage 128 bytes.

-- Statement-level: one update of the usage row per statement, taken after
-- every row lock of that statement, never for a statement that changed nothing.
create function custody.count_deposits() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
    v_bytes bigint;
begin
    if tg_op = 'INSERT' then
        select coalesce(sum(octet_length(n.payload) + 192), 0) into v_bytes from new_deposits n;
    else
        select -coalesce(sum(octet_length(o.payload) + 192), 0) into v_bytes from old_deposits o;
    end if;
    if v_bytes <> 0 then
        update custody.usage set used_bytes = used_bytes + v_bytes;
    end if;
    return null;
end $$;

create function custody.count_requests() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
    v_bytes bigint;
begin
    if tg_op = 'INSERT' then
        select coalesce(sum(octet_length(n.recipient_key) + 128), 0) into v_bytes from new_requests n;
    else
        select -coalesce(sum(octet_length(o.recipient_key) + 128), 0) into v_bytes from old_requests o;
    end if;
    if v_bytes <> 0 then
        update custody.usage set used_bytes = used_bytes + v_bytes;
    end if;
    return null;
end $$;

create function custody.count_chunks() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
    v_rows bigint;
    v_size bigint;
begin
    if tg_op = 'INSERT' then
        select count(*), coalesce(sum(n.size), 0) into v_rows, v_size from new_chunks n;
    else
        select -count(*), -coalesce(sum(o.size), 0) into v_rows, v_size from old_chunks o;
    end if;
    if v_rows <> 0 then
        update custody.usage set used_bytes = used_bytes + v_rows * 192, chunk_bytes = chunk_bytes + v_size;
    end if;
    return null;
end $$;

create function custody.count_garbage() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
    v_rows bigint;
    v_size bigint;
begin
    if tg_op = 'INSERT' then
        select count(*), coalesce(sum(n.size), 0) into v_rows, v_size from new_garbage n;
    else
        select -count(*), -coalesce(sum(o.size), 0) into v_rows, v_size from old_garbage o;
    end if;
    if v_rows <> 0 then
        update custody.usage set used_bytes = used_bytes + v_rows * 128, chunk_bytes = chunk_bytes + v_size;
    end if;
    return null;
end $$;

-- The relay may be writing while this runs: count what is there and start
-- counting changes in one locked step, so nothing is missed or counted twice.
do $$
begin
    lock table custody.deposits, custody.requests, custody.chunks, custody.garbage in share row exclusive mode;
    insert into custody.usage (used_bytes, chunk_bytes)
    select coalesce((select sum(octet_length(d.payload) + 192) from custody.deposits d), 0)
         + coalesce((select sum(octet_length(r.recipient_key) + 128) from custody.requests r), 0)
         + 192 * (select count(*) from custody.chunks)
         + 128 * (select count(*) from custody.garbage),
           coalesce((select sum(c.size) from custody.chunks c), 0)
         + coalesce((select sum(g.size) from custody.garbage g), 0);
    create trigger deposits_counted_in after insert on custody.deposits
        referencing new table as new_deposits for each statement execute function custody.count_deposits();
    create trigger deposits_counted_out after delete on custody.deposits
        referencing old table as old_deposits for each statement execute function custody.count_deposits();
    create trigger requests_counted_in after insert on custody.requests
        referencing new table as new_requests for each statement execute function custody.count_requests();
    create trigger requests_counted_out after delete on custody.requests
        referencing old table as old_requests for each statement execute function custody.count_requests();
    create trigger chunks_counted_in after insert on custody.chunks
        referencing new table as new_chunks for each statement execute function custody.count_chunks();
    create trigger chunks_counted_out after delete on custody.chunks
        referencing old table as old_chunks for each statement execute function custody.count_chunks();
    create trigger garbage_counted_in after insert on custody.garbage
        referencing new table as new_garbage for each statement execute function custody.count_garbage();
    create trigger garbage_counted_out after delete on custody.garbage
        referencing old table as old_garbage for each statement execute function custody.count_garbage();
end $$;

-- The ceiling reads the counter instead of summing the tables.
create or replace function custody.used_bytes() returns bigint
language sql stable set search_path = '' as $$
    select u.used_bytes from custody.usage u
$$;

-- One statement, so every row lock is taken before the usage row: the purge
-- never waits on a row while holding the counter others need.
create or replace function custody.purge_expired() returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_gone bigint;
begin
    with deposits as (
        delete from custody.deposits where expires_at <= now() returning 1
    ), requests as (
        delete from custody.requests where expires_at <= now() returning 1
    )
    select (select count(*) from deposits) + (select count(*) from requests) into v_gone;
    return v_gone;
end $$;

-- A chunk that goes leaves its object, with its size, in the garbage; the
-- column default holds it back five minutes.
create or replace function custody.chunk_gone() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
    insert into custody.garbage (object, size) values (old.object, old.size) on conflict do nothing;
    return null;
end $$;

-- Whether a chunk of p_size bytes fits position p_idx of a file of p_count
-- chunks: what a sealer makes, full unless it is the last.
create function custody.chunk_fits(p_idx smallint, p_count smallint, p_size integer) returns boolean
language sql immutable security definer set search_path = '' as $$
    select p_idx >= 0 and p_idx < p_count
       and p_size - 16 between 256 and 1048576 and ((p_size - 16) & (p_size - 17)) = 0
       and (p_idx = p_count - 1 or p_size = 1048592);
$$;

-- Whether the live, unopened deposit p_id still takes chunk p_idx of p_size bytes.
create function custody.takes_chunk(p_id bytea, p_idx smallint, p_size integer) returns boolean
language sql stable security definer set search_path = '' as $$
    select exists (
        select 1 from custody.deposits d
        where d.id = p_id and d.expires_at > now() and d.claim_digest is null
          and custody.chunk_fits(p_idx, d.chunk_count, p_size)
          and not exists (select 1 from custody.chunks c where c.deposit_id = d.id and c.idx = p_idx)
    );
$$;

-- Refuses past 5 GiB of chunks and garbage objects together. Called under
-- the chunk lock, by everything that adds to them.
create function custody.ensure_chunk_room(p_size integer) returns void
language plpgsql security definer set search_path = '' as $$
begin
    if (select u.chunk_bytes from custody.usage u) + p_size > 5::bigint * 1024 * 1024 * 1024 then
        raise exception 'chunk storage full' using errcode = '53100';
    end if;
end $$;

-- Before the relay stores a chunk: false, and nothing written anywhere, when
-- the deposit does not take it; otherwise the object is recorded as garbage
-- due in fifteen minutes, so it is collected unless record_chunk claims it.
create function custody.reserve_chunk(p_id bytea, p_idx smallint, p_object bytea, p_size integer) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    if not custody.takes_chunk(p_id, p_idx, p_size) then
        return false;
    end if;
    perform pg_advisory_xact_lock(7135340241);
    perform custody.ensure_room(192);
    perform custody.ensure_chunk_room(p_size);
    insert into custody.garbage (object, size, not_before) values (p_object, p_size, now() + interval '15 minutes');
    return true;
end $$;

-- After the relay stored it: chunk p_idx of p_id is the reserved object.
-- False when the reservation is gone or stale (its object may be on its way
-- out of R2), or the deposit no longer takes that chunk.
create function custody.record_chunk(p_id bytea, p_idx smallint, p_object bytea, p_size integer) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    -- Row locks first, the usage row last.
    perform 1 from custody.garbage g
    where g.object = p_object and g.size = p_size and g.not_before > now() + interval '10 minutes'
    for update;
    if not found then
        return false;
    end if;
    perform 1 from custody.deposits d
    where d.id = p_id and d.expires_at > now() and d.claim_digest is null
      and custody.chunk_fits(p_idx, d.chunk_count, p_size)
    for no key update;
    if not found then
        return false;
    end if;
    insert into custody.chunks (deposit_id, idx, object, size) values (p_id, p_idx, p_object, p_size)
    on conflict (deposit_id, idx) do nothing;
    if not found then
        return false;
    end if;
    delete from custody.garbage g where g.object = p_object;
    update custody.deposits d
    set expires_at = d.expires_when_complete, expires_when_complete = null
    where d.id = p_id and d.expires_when_complete is not null and custody.complete(d.id, d.chunk_count);
    return true;
end $$;

-- The deployed relay's one-step form: same rules, counted the new way, and
-- a chunk already in is a refusal like any other.
create or replace function custody.put_chunk(p_id bytea, p_idx smallint, p_object bytea, p_size integer) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    perform pg_advisory_xact_lock(7135340241);
    perform 1 from custody.deposits d
    where d.id = p_id and d.expires_at > now() and d.claim_digest is null
      and custody.chunk_fits(p_idx, d.chunk_count, p_size)
    for no key update;
    if not found then
        return false;
    end if;
    perform custody.ensure_room(192);
    perform custody.ensure_chunk_room(p_size);
    insert into custody.chunks (deposit_id, idx, object, size) values (p_id, p_idx, p_object, p_size)
    on conflict (deposit_id, idx) do nothing;
    if not found then
        return false;
    end if;
    update custody.deposits d
    set expires_at = d.expires_when_complete, expires_when_complete = null
    where d.id = p_id and d.expires_when_complete is not null and custody.complete(d.id, d.chunk_count);
    return true;
end $$;

-- The R2 object of one chunk of a complete file, and whether it burns once
-- handed out. Burns nothing: see burn_chunk.
create function custody.find_chunk(p_id bytea, p_idx smallint, p_claim_digest bytea)
returns table (object bytea, burns boolean)
language sql stable security definer set search_path = '' as $$
    select c.object, d.burn_after_reading
    from custody.deposits d
    join custody.chunks c on c.deposit_id = d.id and c.idx = p_idx
    where d.id = p_id and d.expires_at > now()
      and case when d.burn_after_reading then d.claim_digest = p_claim_digest
               else custody.complete(d.id, d.chunk_count) end;
$$;

-- Burns chunk p_idx of a claimed burn-after-reading file, once R2 delivered
-- it. True for exactly one caller: only that one hands the chunk out.
create function custody.burn_chunk(p_id bytea, p_idx smallint, p_claim_digest bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    -- The row lock serializes the burns of one file, so the one that takes
    -- the last chunk sees that it is the last.
    perform 1 from custody.deposits d
    where d.id = p_id and d.burn_after_reading and d.expires_at > now() and d.claim_digest = p_claim_digest
    for update;
    if not found then
        return false;
    end if;
    delete from custody.chunks c where c.deposit_id = p_id and c.idx = p_idx;
    if not found then
        return false;
    end if;
    if not exists (select 1 from custody.chunks c where c.deposit_id = p_id) then
        delete from custody.deposits d where d.id = p_id;
    end if;
    return true;
end $$;

-- Revokes like custody.revoke, and names the objects of the chunks that went,
-- so the relay deletes them from R2 at once. Null when nothing was revoked.
create function custody.revoke_with_objects(p_id bytea, p_revocation_digest bytea) returns bytea[]
language plpgsql security definer set search_path = '' as $$
declare
    v_objects bytea[];
begin
    perform 1 from custody.deposits d
    where d.id = p_id and d.revocation_digest = p_revocation_digest and d.expires_at > now()
    for update;
    if not found then
        return null;
    end if;
    select coalesce(array_agg(c.object), '{}') into v_objects from custody.chunks c where c.deposit_id = p_id;
    delete from custody.deposits d where d.id = p_id;
    return v_objects;
end $$;

-- Only what is due: a reserved upload or a chunk that just went waits.
create or replace function custody.garbage(p_limit integer) returns setof bytea
language sql security definer set search_path = '' as $$
    select g.object from custody.garbage g
    where g.not_before <= now()
    limit least(greatest(p_limit, 0), 1000);
$$;

revoke execute on all functions in schema custody from public;
grant execute on function
    custody.reserve_chunk(bytea, smallint, bytea, integer),
    custody.record_chunk(bytea, smallint, bytea, integer),
    custody.find_chunk(bytea, smallint, bytea),
    custody.burn_chunk(bytea, smallint, bytea),
    custody.revoke_with_objects(bytea, bytea)
to sigylo_relay;
