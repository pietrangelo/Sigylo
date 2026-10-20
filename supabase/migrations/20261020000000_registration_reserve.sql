-- Sigylo access: a flood of logins no longer stops registrations (bug hunt
-- of 2026-10-20).
--
-- Registering a free name spends its own budget (access.admit), and that
-- budget's counter is a transient row, like the logins a flood parks. With
-- the transient store full, every register/start was refused as Throttled,
-- against the promise that a login flood never stops new accounts. The
-- registration budget now counts against the transient ceiling plus a
-- reserve of its own (1 MiB, about 8000 counters), which logins and
-- sessions cannot reach. The reserve has an end too: a flood of
-- registrations still meets a ceiling.
--
-- Compatible with the relay already deployed: access.admit(bytea, integer)
-- and access.ensure_room(bigint, boolean) keep their signature and behaviour;
-- the new relay calls access.admit(bytea, integer, boolean).

begin;

-- PL/pgSQL, not SQL, so a new value reaches plans already cached (see access.capacity_bytes).
create function access.registration_reserve_bytes() returns bigint
language plpgsql stable set search_path = '' as $$
begin
    return 1024 * 1024;
end $$;

-- access.ensure_room, with p_reserve bytes beyond the ceiling.
create function access.ensure_room(p_bytes bigint, p_transient boolean, p_reserve bigint) returns void
language plpgsql set search_path = '' as $$
declare
    v_used bigint;
    v_capacity bigint;
begin
    if p_bytes <= 0 then
        return;
    end if;
    if p_transient then
        v_capacity := access.transient_capacity_bytes() + p_reserve;
    else
        v_capacity := access.capacity_bytes() + p_reserve;
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

create or replace function access.ensure_room(p_bytes bigint, p_transient boolean) returns void
language plpgsql set search_path = '' as $$
begin
    perform access.ensure_room(p_bytes, p_transient, 0);
end $$;

-- access.admit for one budget; p_registration lets its counter draw on the
-- registration reserve.
create function access.admit(p_account bytea, p_limit integer, p_registration boolean) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
    v_attempts integer;
begin
    if p_limit is null or p_limit < 1 or p_limit > 1000 or p_registration is null then
        raise exception 'limit out of range' using errcode = '22023';
    end if;
    if not exists (select 1 from access.attempts t where t.account = p_account) then
        perform access.ensure_room(access.row_cost('attempts'), true,
            case when p_registration then access.registration_reserve_bytes() else 0 end);
    end if;
    insert into access.attempts as t (account, window_start, attempts)
    values (p_account, now(), 1)
    on conflict (account) do update set
        window_start = case when t.window_start <= now() - interval '1 minute' then now() else t.window_start end,
        attempts = case when t.window_start <= now() - interval '1 minute' then 1 else t.attempts + 1 end
    returning t.attempts into v_attempts;
    return v_attempts <= p_limit;
end $$;

create or replace function access.admit(p_account bytea, p_limit integer) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
    return access.admit(p_account, p_limit, false);
end $$;

revoke execute on function
    access.registration_reserve_bytes(),
    access.ensure_room(bigint, boolean, bigint),
    access.admit(bytea, integer, boolean)
from public;
grant execute on function access.admit(bytea, integer, boolean) to sigylo_relay;

commit;
