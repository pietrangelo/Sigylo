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
        'update custody.deposits set claim_digest = null',
        'select custody.lifetime(300)',
        'select custody.complete(''\x00''::bytea, 0::smallint)'
    ] loop
        begin
            execute attempt;
            raise exception 'relay was allowed to run: %', attempt;
        exception when insufficient_privilege then
            null; -- expected
        end;
    end loop;
end $$;
