-- Sigylo access: closing an account takes its locks in the same order as
-- every other writer (bug hunt of 2026-10-20).
--
-- access.open_session and access.store_keyring lock the account row first and
-- then the usage counter (through the counting triggers). access.close_account
-- deleted the logins in progress first, which locks the usage counter, and
-- only then the account: run against a sign-in on the same account, the two
-- could deadlock, and PostgreSQL aborted one of them (a sporadic 503, nothing
-- lost). The account row is now locked first.
--
-- Compatible with the relay already deployed: same signature and result.

begin;

create or replace function access.close_account(p_digest bytea) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
    v_account bytea;
begin
    select s.account into v_account from access.sessions s
    where s.digest = p_digest and s.expires_at > now();
    if not found then
        return false;
    end if;
    perform 1 from access.accounts a where a.account = v_account for update;
    delete from access.logins l where l.account = v_account;
    delete from access.accounts a where a.account = v_account;
    return true;
end $$;

commit;
