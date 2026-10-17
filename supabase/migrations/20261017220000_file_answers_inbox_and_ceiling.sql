-- Files met the private inbox and the custody ceiling only once both were in
-- main, so two gaps remained:
--
-- * the six-argument custody.deposit (files) never called ensure_room, and the
--   relay sends every deposit through it, so the ceiling held nothing back;
-- * custody.answer_request(..., smallint) filed every answer under the public
--   request id, where whoever saw the request link could burn it, read it, or
--   push a junk chunk ahead of the sender.
--
-- custody.answer_into_inbox answers into the inbox and tells the one who
-- answered where that is, so the sender, and only the sender, can upload the
-- chunks of a file answer. The older answer functions stay for the relay that
-- is deployed while this migration is applied.

create or replace function custody.deposit(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean,
    p_lifetime_seconds integer, p_revocation_digest bytea, p_chunk_count smallint
) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
    v_expires timestamptz;
begin
    perform custody.ensure_room(octet_length(p_payload));
    -- An expired row is gone in every observable way; let its id be reused.
    delete from custody.deposits where id = p_id and expires_at <= now();
    insert into custody.deposits (id, payload, burn_after_reading, revocation_digest, expires_at, chunk_count)
    values (p_id, p_payload, p_burn_after_reading, p_revocation_digest,
            now() + custody.lifetime(p_lifetime_seconds), p_chunk_count)
    returning expires_at into v_expires;
    return extract(epoch from v_expires)::bigint;
end $$;

-- Consumes the live request p_id and files the answer in its inbox (under the
-- request id for requests posted before inboxes). No row when there was no
-- live request to answer.
create function custody.answer_into_inbox(
    p_id bytea, p_payload bytea, p_burn_after_reading boolean, p_lifetime_seconds integer, p_chunk_count smallint
) returns table (inbox bytea, expires_at bigint)
language plpgsql security definer set search_path = '' as $$
declare
    v_inbox bytea;
begin
    delete from custody.requests r where r.id = p_id and r.expires_at > now()
    returning coalesce(r.inbox_id, r.id) into v_inbox;
    if not found then
        return;
    end if;
    return query select v_inbox,
        custody.deposit(v_inbox, p_payload, p_burn_after_reading, p_lifetime_seconds, null, p_chunk_count);
end $$;

revoke execute on function custody.answer_into_inbox(bytea, bytea, boolean, integer, smallint) from public;
grant execute on function custody.answer_into_inbox(bytea, bytea, boolean, integer, smallint) to sigylo_relay;
