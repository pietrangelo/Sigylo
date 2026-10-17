-- Sigylo custody: answers go to a private inbox, not under the request's id.
--
-- The request link travels to the sender, often over a channel others can
-- read. While the answer was filed under the request's own id, whoever held
-- that link could POST /open on it and burn the answer before the recipient
-- (or fetch its ciphertext). Each request now carries a second relay-chosen
-- id, known only to the recipient's private link, and the answer is filed
-- there.
--
-- Rollout: apply this migration, then deploy the relay. The old relay keeps
-- working meanwhile (its three-argument post_request leaves inbox_id null),
-- and requests without an inbox are still answered under their own id, so
-- links handed out before this change keep working. A later migration drops
-- the three-argument function once no relay calls it.

alter table custody.requests
    add column inbox_id bytea check (inbox_id is null or (octet_length(inbox_id) = 16 and inbox_id <> id));

create function custody.post_request(
    p_id bytea, p_inbox_id bytea, p_recipient_key bytea, p_lifetime_seconds integer
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    if p_inbox_id is null then
        raise exception 'inbox id required' using errcode = '22023';
    end if;
    delete from custody.requests where id = p_id and expires_at <= now();
    insert into custody.requests (id, inbox_id, recipient_key, expires_at)
    values (p_id, p_inbox_id, p_recipient_key, now() + custody.lifetime(p_lifetime_seconds))
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

-- Consume the request and file the answer in its inbox, atomically.
-- Returns null when there is no live request (never existed, expired, answered).
create or replace function custody.answer_request(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean, p_lifetime_seconds integer
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_inbox bytea;
begin
    delete from custody.requests where id = p_id and expires_at > now()
    returning coalesce(inbox_id, id) into v_inbox;
    if not found then
        return null;
    end if;
    return custody.deposit(v_inbox, p_payload, p_burn_after_reading, p_lifetime_seconds, null);
end $$;

revoke execute on function custody.post_request(bytea, bytea, bytea, integer) from public;
grant execute on function custody.post_request(bytea, bytea, bytea, integer) to sigylo_relay;
