-- Run as sigylo_relay (adversary: a leaked relay credential).
-- Every direct table access must fail; only the functions are reachable.
do $$
declare
    attempt text;
begin
    foreach attempt in array array[
        'select count(*) from custody.deposits',
        'select * from custody.requests',
        'delete from custody.deposits',
        'update custody.deposits set expires_at = now() + interval ''1 year''',
        'insert into custody.requests values (''\x00''::bytea, ''\x00''::bytea, now())',
        'truncate custody.deposits',
        'select count(*) from custody.chunks',
        'delete from custody.chunks',
        'select object from custody.chunks',
        'select * from custody.garbage',
        'delete from custody.garbage',
        'insert into custody.garbage values (''\x00''::bytea)',
        'update custody.deposits set claim_digest = null',
        'select custody.lifetime(300)',
        'select custody.complete(''\x00''::bytea, 0::smallint)',
        'select custody.used_bytes()',
        'select custody.ensure_room(0)',
        'select * from custody.usage',
        'update custody.usage set used_bytes = 0, chunk_bytes = 0',
        'delete from custody.usage',
        'update custody.garbage set not_before = now()',
        'select custody.chunk_fits(0::smallint, 1::smallint, 272)',
        'select custody.takes_chunk(''\x00''::bytea, 0::smallint, 272)',
        'select custody.ensure_chunk_room(0)'
    ] loop
        begin
            execute attempt;
            raise exception 'relay was allowed to run: %', attempt;
        exception when insufficient_privilege then
            null; -- expected
        end;
    end loop;
end $$;

-- Same for accounts: a leaked relay credential cannot list or dump them.
do $$
declare
    attempt text;
begin
    foreach attempt in array array[
        'select count(*) from access.accounts',
        'select record from access.accounts',
        'select * from access.sessions',
        'select * from access.logins',
        'update access.accounts set keyring = null',
        'delete from access.sessions',
        'insert into access.sessions values (''\x00''::bytea, ''\x00''::bytea, now())',
        'truncate access.accounts',
        'select access.lifetime(300)'
    ] loop
        begin
            execute attempt;
            raise exception 'relay was allowed to run: %', attempt;
        exception when insufficient_privilege then
            null; -- expected
        end;
    end loop;
end $$;
