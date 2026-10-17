-- Sigylo access, hardening after the security review of 2026-10-17.
--
-- 1. A ceiling on what accounts may hold. Accounts never expire, and a flood
--    of registrations (or of logins for made-up names) would otherwise grow
--    the database to the free plan's 500 MB, where it turns read-only and
--    nothing, custody included, works any more. Two budgets, each refused
--    with SQLSTATE 53100 (disk_full), which the relay reports as 507
--    StorageFull:
--      * stored: accounts and their keyrings, 64 MiB;
--      * transient: logins in progress, sessions and attempt counters,
--        16 MiB, so a flood of logins can never stop new accounts, nor a
--        full account store stop people from logging in.
--    Logging in, reading a keyring, writing one no larger than before,
--    signing out and closing an account keep working when full.
--    The bytes are kept in a running counter (access.usage), updated by
--    triggers, so checking the ceiling never scans a table. Each row counts
--    a fixed cost for its key, record, indexes and overhead, plus its
--    keyring: a million tiny rows weigh what they weigh on disk.
--
-- 2. A global login budget per account (access.admit). Cloudflare's rate
--    limiter counts per location: spread over many, an attacker gets far
--    more than 10 guesses a minute. This counter lives in the database and
--    holds, per account hash, only the start of the current one-minute
--    window and the attempts in it; the cron deletes it once the window is
--    over. No address, no name.
--
-- 3. Sessions last at most 12 hours (the relay's SESSION_SECONDS), whoever
--    calls open_session.
--
-- Compatible with the relay already deployed: it calls the same functions
-- with the same arguments, and reads a refusal as StoreUnavailable until the
-- new relay is out.

begin;

create table access.usage (
    id        boolean primary key default true check (id),
    stored    bigint  not null check (stored >= 0),
    transient bigint  not null check (transient >= 0)
);

create table access.attempts (
    account      bytea       primary key check (octet_length(account) = 32),
    window_start timestamptz not null,
    attempts     integer     not null check (attempts >= 1)
);
create index attempts_window_start on access.attempts (window_start);

alter table access.usage enable row level security;
alter table access.attempts enable row level security;
alter table access.usage force row level security;
alter table access.attempts force row level security;
revoke all on access.usage, access.attempts from public;

-- What a row weighs, in bytes: key, record or state, indexes and tuple overhead.
create function access.row_cost(p_table text) returns bigint
language plpgsql immutable set search_path = '' as $$
begin
    return case p_table
        when 'accounts' then 512
        when 'logins' then 384
        when 'sessions' then 192
        when 'attempts' then 128
    end;
end $$;

-- PL/pgSQL, not SQL, so a new ceiling reaches plans already cached (see custody.capacity_bytes).
create function access.capacity_bytes() returns bigint
language plpgsql stable set search_path = '' as $$
begin
    return 64 * 1024 * 1024;
end $$;

create function access.transient_capacity_bytes() returns bigint
language plpgsql stable set search_path = '' as $$
begin
    return 16 * 1024 * 1024;
end $$;

create function access.count_stored() returns trigger
language plpgsql set search_path = '' as $$
declare
    v_delta bigint := 0;
begin
    if tg_op in ('INSERT', 'UPDATE') then
        v_delta := v_delta + access.row_cost('accounts') + coalesce(octet_length(new.keyring), 0);
    end if;
    if tg_op in ('DELETE', 'UPDATE') then
        v_delta := v_delta - access.row_cost('accounts') - coalesce(octet_length(old.keyring), 0);
    end if;
    if v_delta <> 0 then
        update access.usage set stored = stored + v_delta;
    end if;
    return null;
end $$;

create function access.count_transient() returns trigger
language plpgsql set search_path = '' as $$
begin
    update access.usage
    set transient = transient + case tg_op when 'INSERT' then 1 else -1 end * access.row_cost(tg_table_name);
    return null;
end $$;

create trigger count_stored after insert or update of keyring or delete on access.accounts
    for each row execute function access.count_stored();
create trigger count_transient after insert or delete on access.logins
    for each row execute function access.count_transient();
create trigger count_transient after insert or delete on access.sessions
    for each row execute function access.count_transient();
create trigger count_transient after insert or delete on access.attempts
    for each row execute function access.count_transient();

-- The counter starts from what is there now; the lock keeps writers out
-- until the triggers above are in place and the sums are taken.
lock table access.accounts, access.logins, access.sessions in share row exclusive mode;
insert into access.usage (stored, transient) values (
    (select count(*) * access.row_cost('accounts') + coalesce(sum(octet_length(keyring)), 0) from access.accounts),
    (select count(*) * access.row_cost('logins') from access.logins)
        + (select count(*) * access.row_cost('sessions') from access.sessions)
);

-- Refuses p_bytes more of the given budget with 53100 when it would not fit,
-- after purging what expired.
create function access.ensure_room(p_bytes bigint, p_transient boolean) returns void
language plpgsql set search_path = '' as $$
declare
    v_used bigint;
    v_capacity bigint;
begin
    if p_bytes <= 0 then
        return;
    end if;
    if p_transient then
        v_capacity := access.transient_capacity_bytes();
    else
        v_capacity := access.capacity_bytes();
    end if;
    for attempt in 1..2 loop
        select case when p_transient then u.transient else u.stored end into v_used from access.usage u;
        if v_used + p_bytes <= v_capacity then
            return;
        end if;
        if attempt = 1 then
            perform access.purge_expired();
        end if;
    end loop;
    raise exception 'account storage full' using errcode = '53100';
end $$;

create or replace function access.enroll(p_account bytea, p_record bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    if exists (select 1 from access.accounts a where a.account = p_account) then
        return false;
    end if;
    perform access.ensure_room(access.row_cost('accounts'), false);
    insert into access.accounts (account, record) values (p_account, p_record)
    on conflict (account) do nothing;
    return found;
end $$;

create or replace function access.park_login(p_handle bytea, p_account bytea, p_state bytea, p_seconds integer)
returns void
language plpgsql security definer set search_path = '' as $$
begin
    perform access.ensure_room(access.row_cost('logins'), true);
    insert into access.logins (handle, account, state, expires_at)
    values (p_handle, p_account, p_state, now() + access.lifetime(p_seconds));
end $$;

-- Null when the account no longer exists.
create or replace function access.open_session(p_digest bytea, p_account bytea, p_seconds integer) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    if p_seconds is null or p_seconds > 43200 then
        raise exception 'session lifetime out of range' using errcode = '22023';
    end if;
    perform access.ensure_room(access.row_cost('sessions'), true);
    insert into access.sessions (digest, account, expires_at)
    select p_digest, a.account, now() + access.lifetime(p_seconds)
    from access.accounts a where a.account = p_account
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

-- As before; a larger keyring needs room for the difference only, so a full
-- store never stops anyone from writing a keyring no larger than theirs.
create or replace function access.store_keyring(p_digest bytea, p_keyring bytea, p_expected bigint) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_account bytea;
    v_version bigint;
    v_old integer;
begin
    select s.account into v_account from access.sessions s
    where s.digest = p_digest and s.expires_at > now();
    if not found then
        return null;
    end if;
    select coalesce(octet_length(a.keyring), 0) into v_old from access.accounts a where a.account = v_account;
    perform access.ensure_room(coalesce(octet_length(p_keyring), 0) - coalesce(v_old, 0), false);
    update access.accounts a
    set keyring = p_keyring, keyring_version = a.keyring_version + 1
    where a.account = v_account and a.keyring_version = p_expected
    returning a.keyring_version into v_version;
    if not found then
        return -1;
    end if;
    return v_version;
end $$;

-- One attempt against the account's budget: true while the current
-- one-minute window holds at most p_limit attempts. Atomic, so concurrent
-- attempts from anywhere in the world are counted once each.
create function access.admit(p_account bytea, p_limit integer) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
    v_attempts integer;
begin
    if p_limit is null or p_limit < 1 or p_limit > 1000 then
        raise exception 'limit out of range' using errcode = '22023';
    end if;
    if not exists (select 1 from access.attempts t where t.account = p_account) then
        perform access.ensure_room(access.row_cost('attempts'), true);
    end if;
    insert into access.attempts as t (account, window_start, attempts)
    values (p_account, now(), 1)
    on conflict (account) do update set
        window_start = case when t.window_start <= now() - interval '1 minute' then now() else t.window_start end,
        attempts = case when t.window_start <= now() - interval '1 minute' then 1 else t.attempts + 1 end
    returning t.attempts into v_attempts;
    return v_attempts <= p_limit;
end $$;

create or replace function access.purge_expired() returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_logins bigint;
    v_sessions bigint;
    v_attempts bigint;
begin
    delete from access.logins where expires_at <= now();
    get diagnostics v_logins = row_count;
    delete from access.sessions where expires_at <= now();
    get diagnostics v_sessions = row_count;
    delete from access.attempts where window_start <= now() - interval '1 minute';
    get diagnostics v_attempts = row_count;
    return v_logins + v_sessions + v_attempts;
end $$;

-- Helpers run only inside the functions above, as their owner.
revoke execute on function
    access.row_cost(text),
    access.capacity_bytes(),
    access.transient_capacity_bytes(),
    access.count_stored(),
    access.count_transient(),
    access.ensure_room(bigint, boolean),
    access.admit(bytea, integer)
from public;
grant execute on function access.admit(bytea, integer) to sigylo_relay;

commit;
