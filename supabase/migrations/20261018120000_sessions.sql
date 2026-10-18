-- Sigylo access: sign out everywhere, and at most 16 sessions per account
-- (security review of 2026-10-17, I4).
--
-- 1. access.close_sessions ends every session of the account behind a live
--    session, this one included: a token that may have been stolen stops
--    working at once, without closing the account and losing its keyring.
-- 2. access.open_session keeps at most 16 sessions per account; one more
--    ends the one that expires first, never the new one. A stolen password
--    can no longer pile up sessions, and the person's own logins always
--    get in.
--
-- Compatible with the relay already deployed: open_session keeps its
-- signature, and close_sessions is new.

begin;

-- Null when the account no longer exists. The account row is locked, so
-- concurrent logins to one account count their sessions one at a time.
create or replace function access.open_session(p_digest bytea, p_account bytea, p_seconds integer) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    if p_seconds is null or p_seconds > 43200 then
        raise exception 'session lifetime out of range' using errcode = '22023';
    end if;
    perform 1 from access.accounts a where a.account = p_account for update;
    if not found then
        return null;
    end if;
    perform access.ensure_room(access.row_cost('sessions'), true);
    insert into access.sessions (digest, account, expires_at)
    values (p_digest, p_account, now() + access.lifetime(p_seconds))
    returning expires_at into v_expires;
    delete from access.sessions s
    where s.digest in (
        select o.digest from access.sessions o
        where o.account = p_account and o.digest <> p_digest
        order by o.expires_at desc, o.digest
        offset 15
    );
    return extract(epoch from v_expires)::bigint;
end $$;

-- False when there is no live session behind the digest.
create function access.close_sessions(p_digest bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
    v_account bytea;
begin
    select s.account into v_account from access.sessions s
    where s.digest = p_digest and s.expires_at > now();
    if not found then
        return false;
    end if;
    delete from access.sessions s where s.account = v_account;
    return true;
end $$;

revoke execute on function access.close_sessions(bytea) from public;
grant execute on function access.close_sessions(bytea) to sigylo_relay;

commit;
