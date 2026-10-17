-- Sigylo access: accounts with OPAQUE login, sessions and the blind keyring.
--
-- OPAQUE (RFC 9807) means the password never reaches the relay, not even
-- hashed. What the database keeps per account:
--
--   * `account`: a keyed hash (HMAC with a relay secret) of the username, so
--     a dump does not reveal who has an account, not even by guessing names;
--   * `record`: the OPAQUE registration record, useless without both the
--     password and the relay's OPRF key (a Worker secret, not in here);
--   * `keyring`: an envelope sealed on the device with a key the relay never
--     sees, and a version counter so two devices never overwrite each other.
--
-- Logins in progress live five minutes, sessions twelve hours, and both are
-- kept only as random handles or SHA-256 digests of the bearer token. No
-- username, no password, no e-mail, no IP address, no creation time.
--
-- As for custody, the relay role can only execute the functions below.

create schema if not exists access;

create table access.accounts (
    account         bytea  primary key check (octet_length(account) = 32),
    record          bytea  not null check (octet_length(record) = 192),
    keyring         bytea  check (keyring is null or octet_length(keyring) between 1 and 73728),
    keyring_version bigint not null default 0 check (keyring_version >= 0)
);

-- No foreign key on purpose: a login for an unknown name is parked too, so
-- that it looks exactly like a login for a real account.
create table access.logins (
    handle     bytea       primary key check (octet_length(handle) = 16),
    account    bytea       not null check (octet_length(account) = 32),
    state      bytea       not null check (octet_length(state) = 168),
    expires_at timestamptz not null
);
create index logins_expires_at on access.logins (expires_at);

create table access.sessions (
    digest     bytea       primary key check (octet_length(digest) = 32),
    account    bytea       not null references access.accounts (account) on delete cascade,
    expires_at timestamptz not null
);
create index sessions_expires_at on access.sessions (expires_at);
create index sessions_account on access.sessions (account);

alter table access.accounts enable row level security;
alter table access.logins enable row level security;
alter table access.sessions enable row level security;
alter table access.accounts force row level security;
alter table access.logins force row level security;
alter table access.sessions force row level security;
revoke all on schema access from public;
revoke all on all tables in schema access from public;

create function access.lifetime(p_seconds integer) returns interval
language plpgsql immutable set search_path = '' as $$
begin
    if p_seconds is null or p_seconds < 1 or p_seconds > 86400 then
        raise exception 'lifetime out of range' using errcode = '22023';
    end if;
    return make_interval(secs => p_seconds);
end $$;

-- False when the account exists: a registration never overwrites one.
create function access.enroll(p_account bytea, p_record bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    insert into access.accounts (account, record) values (p_account, p_record)
    on conflict (account) do nothing;
    return found;
end $$;

create function access.registration(p_account bytea) returns bytea
language sql stable security definer set search_path = '' as $$
    select a.record from access.accounts a where a.account = p_account;
$$;

create function access.park_login(p_handle bytea, p_account bytea, p_state bytea, p_seconds integer)
returns void
language sql security definer set search_path = '' as $$
    insert into access.logins (handle, account, state, expires_at)
    values (p_handle, p_account, p_state, now() + access.lifetime(p_seconds));
$$;

-- Single use: the row goes whatever happens next, and only a live one is returned.
create function access.take_login(p_handle bytea)
returns table (account bytea, state bytea)
language sql security definer set search_path = '' as $$
    with taken as (
        delete from access.logins l where l.handle = p_handle
        returning l.account, l.state, l.expires_at
    )
    select t.account, t.state from taken t where t.expires_at > now();
$$;

-- Null when the account no longer exists.
create function access.open_session(p_digest bytea, p_account bytea, p_seconds integer) returns bigint
language sql security definer set search_path = '' as $$
    insert into access.sessions (digest, account, expires_at)
    select p_digest, a.account, now() + access.lifetime(p_seconds)
    from access.accounts a where a.account = p_account
    returning extract(epoch from expires_at)::bigint;
$$;

create function access.close_session(p_digest bytea) returns void
language sql security definer set search_path = '' as $$
    delete from access.sessions s where s.digest = p_digest;
$$;

-- No row when there is no live session behind the digest.
create function access.keyring(p_digest bytea)
returns table (keyring bytea, version bigint)
language sql stable security definer set search_path = '' as $$
    select a.keyring, a.keyring_version
    from access.sessions s join access.accounts a on a.account = s.account
    where s.digest = p_digest and s.expires_at > now();
$$;

-- The new version; -1 when the stored version is not p_expected (another
-- device wrote meanwhile); null when there is no live session. The version
-- check and the write are one UPDATE, so concurrent writers cannot both win.
create function access.store_keyring(p_digest bytea, p_keyring bytea, p_expected bigint) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_account bytea;
    v_version bigint;
begin
    select s.account into v_account from access.sessions s
    where s.digest = p_digest and s.expires_at > now();
    if not found then
        return null;
    end if;
    update access.accounts a
    set keyring = p_keyring, keyring_version = a.keyring_version + 1
    where a.account = v_account and a.keyring_version = p_expected
    returning a.keyring_version into v_version;
    if not found then
        return -1;
    end if;
    return v_version;
end $$;

-- Deletes the account behind a live session: its record, its keyring, every
-- session (cascade) and every login in progress. The name becomes free.
create function access.close_account(p_digest bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
    v_account bytea;
begin
    select s.account into v_account from access.sessions s
    where s.digest = p_digest and s.expires_at > now();
    if not found then
        return false;
    end if;
    delete from access.logins l where l.account = v_account;
    delete from access.accounts a where a.account = v_account;
    return true;
end $$;

create function access.purge_expired() returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_logins bigint;
    v_sessions bigint;
begin
    delete from access.logins where expires_at <= now();
    get diagnostics v_logins = row_count;
    delete from access.sessions where expires_at <= now();
    get diagnostics v_sessions = row_count;
    return v_logins + v_sessions;
end $$;

revoke execute on all functions in schema access from public;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'sigylo_relay') then
        create role sigylo_relay nologin;
    end if;
end $$;

grant usage on schema access to sigylo_relay;
grant execute on function
    access.enroll(bytea, bytea),
    access.registration(bytea),
    access.park_login(bytea, bytea, bytea, integer),
    access.take_login(bytea),
    access.open_session(bytea, bytea, integer),
    access.close_session(bytea),
    access.keyring(bytea),
    access.store_keyring(bytea, bytea, bigint),
    access.close_account(bytea),
    access.purge_expired()
to sigylo_relay;
