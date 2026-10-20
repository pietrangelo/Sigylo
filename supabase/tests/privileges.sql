-- Run as the owner: checks the privilege layout the migration promises.
do $$
begin
    -- The relay may call the functions...
    assert has_function_privilege('sigylo_relay', 'custody.open(bytea)', 'execute'),
        'relay must be able to open';
    assert has_function_privilege('sigylo_relay', 'custody.purge_expired()', 'execute'),
        'relay must be able to purge';
    assert has_function_privilege('sigylo_relay', 'custody.post_request(bytea, bytea, bytea, integer)', 'execute'),
        'relay must be able to post a request with its inbox';
    assert not has_function_privilege('public', 'custody.post_request(bytea, bytea, bytea, integer)', 'execute'),
        'PUBLIC must not post requests';
    assert has_function_privilege('sigylo_relay', 'custody.answer_into_inbox(bytea, bytea, boolean, integer, smallint)', 'execute'),
        'relay must be able to answer into the inbox';
    assert not has_function_privilege('public', 'custody.answer_into_inbox(bytea, bytea, boolean, integer, smallint)', 'execute'),
        'PUBLIC must not answer requests';
    assert has_function_privilege('sigylo_relay', 'custody.open(bytea, bytea)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.put_chunk(bytea, smallint, bytea, integer)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.open_chunk(bytea, smallint, bytea)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.garbage(integer)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.forget_garbage(bytea[])', 'execute'),
        'relay must be able to record, find and clean up file chunks';
    assert not has_function_privilege('sigylo_relay', 'custody.complete(bytea, smallint)', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.chunk_gone()', 'execute'),
        'internal helpers stay internal';
    assert has_function_privilege('sigylo_relay', 'custody.reserve_chunk(bytea, smallint, bytea, integer)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.record_chunk(bytea, smallint, bytea, integer)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.find_chunk(bytea, smallint, bytea)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.burn_chunk(bytea, smallint, bytea)', 'execute')
        and has_function_privilege('sigylo_relay', 'custody.revoke_with_objects(bytea, bytea)', 'execute'),
        'relay must be able to reserve, record, find and burn chunks, and revoke with their objects';
    assert not has_function_privilege('public', 'custody.reserve_chunk(bytea, smallint, bytea, integer)', 'execute')
        and not has_function_privilege('public', 'custody.record_chunk(bytea, smallint, bytea, integer)', 'execute')
        and not has_function_privilege('public', 'custody.find_chunk(bytea, smallint, bytea)', 'execute')
        and not has_function_privilege('public', 'custody.burn_chunk(bytea, smallint, bytea)', 'execute')
        and not has_function_privilege('public', 'custody.revoke_with_objects(bytea, bytea)', 'execute'),
        'PUBLIC must not touch chunks';
    assert not has_function_privilege('sigylo_relay', 'custody.chunk_fits(smallint, smallint, integer)', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.takes_chunk(bytea, smallint, integer)', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.ensure_chunk_room(integer)', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.used_bytes()', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.count_deposits()', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.count_requests()', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.count_chunks()', 'execute')
        and not has_function_privilege('sigylo_relay', 'custody.count_garbage()', 'execute'),
        'the counting and the chunk rules stay internal';
    -- Every function the relay can reach runs as its owner with an empty search_path.
    assert not exists (
        select 1 from pg_proc p
        where p.pronamespace = 'custody'::regnamespace
          and has_function_privilege('sigylo_relay', p.oid, 'execute')
          and not (p.prosecdef and coalesce(p.proconfig, '{}') @> array['search_path=""'])
    ), 'every function the relay calls is SECURITY DEFINER with search_path = ''''';
    assert not has_table_privilege('sigylo_relay', 'custody.usage', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.usage directly';
    assert (select count(*) from custody.usage) = 1, 'custody.usage holds exactly one row';
    -- ...but has no table privilege at all.
    assert not has_table_privilege('sigylo_relay', 'custody.deposits', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.deposits directly';
    assert not has_table_privilege('sigylo_relay', 'custody.requests', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.requests directly';
    assert not has_table_privilege('sigylo_relay', 'custody.chunks', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.chunks directly';
    assert not has_table_privilege('sigylo_relay', 'custody.garbage', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.garbage directly';
    -- Chunks live in R2: the database holds no column that could keep their bytes.
    assert not exists (select 1 from information_schema.columns
                       where table_schema = 'custody' and table_name in ('chunks', 'garbage')
                         and column_name not in ('deposit_id', 'idx', 'object', 'size', 'not_before')),
        'custody.chunks and custody.garbage keep only object names, sizes and when garbage is due';
    assert not exists (select 1 from information_schema.columns
                       where table_schema = 'custody' and table_name = 'usage'
                         and column_name not in ('used_bytes', 'chunk_bytes')),
        'custody.usage keeps only two totals';
    -- PUBLIC (and therefore Supabase anon/authenticated) gets nothing.
    assert not has_function_privilege('public', 'custody.open(bytea)', 'execute'),
        'PUBLIC must not execute custody functions';
    assert not has_schema_privilege('public', 'custody', 'usage'),
        'PUBLIC must not use the custody schema';
    assert (select bool_and(relrowsecurity and relforcerowsecurity) from pg_class
            where relnamespace = 'custody'::regnamespace and relkind = 'r'),
        'RLS must be enabled and forced on every custody table';
    -- Nobody but the owner and the relay holds any privilege on the schema, its
    -- tables or its functions: not PUBLIC, not Supabase's anon, authenticated
    -- or service_role (run.sh creates them with Supabase's default grants).
    assert not exists (
        select 1
        from (
            select coalesce(nspacl, acldefault('n', nspowner)) as acl, nspowner as owner
            from pg_namespace where nspname = 'custody'
            union all
            select coalesce(relacl, acldefault('r', relowner)), relowner
            from pg_class where relnamespace = 'custody'::regnamespace
            union all
            select coalesce(proacl, acldefault('f', proowner)), proowner
            from pg_proc where pronamespace = 'custody'::regnamespace
        ) as objects, aclexplode(objects.acl) as grant_
        where grant_.grantee not in (objects.owner, 'sigylo_relay'::regrole)
    ), 'only the owner and sigylo_relay may hold privileges in the custody schema';
    -- No column can hold plaintext metadata such as creation time or client address.
    assert (select count(*) from information_schema.columns where table_schema = 'custody') = 21,
        'custody tables must keep exactly the 21 documented columns';
end $$;

-- The access schema follows the same layout.
do $$
begin
    assert has_function_privilege('sigylo_relay', 'access.take_login(bytea)', 'execute'),
        'relay must be able to finish logins';
    assert has_function_privilege('sigylo_relay', 'access.store_keyring(bytea, bytea, bigint)', 'execute'),
        'relay must be able to store keyrings';
    assert not has_table_privilege('sigylo_relay', 'access.accounts', 'select,insert,update,delete,truncate'),
        'relay must not touch access.accounts directly';
    assert not has_table_privilege('sigylo_relay', 'access.logins', 'select,insert,update,delete,truncate'),
        'relay must not touch access.logins directly';
    assert not has_table_privilege('sigylo_relay', 'access.sessions', 'select,insert,update,delete,truncate'),
        'relay must not touch access.sessions directly';
    assert not has_table_privilege('sigylo_relay', 'access.attempts', 'select,insert,update,delete,truncate'),
        'relay must not touch access.attempts directly';
    assert not has_table_privilege('sigylo_relay', 'access.usage', 'select,insert,update,delete,truncate'),
        'relay must not touch access.usage directly';
    assert has_function_privilege('sigylo_relay', 'access.close_sessions(bytea)', 'execute'),
        'relay must be able to sign out everywhere';
    assert not has_function_privilege('public', 'access.close_sessions(bytea)', 'execute'),
        'PUBLIC must not execute access.close_sessions';
    assert has_function_privilege('sigylo_relay', 'access.admit(bytea, integer)', 'execute'),
        'relay must count login attempts';
    assert has_function_privilege('sigylo_relay', 'access.admit(bytea, integer, boolean)', 'execute'),
        'relay must count registration attempts';
    assert not has_function_privilege('sigylo_relay', 'access.ensure_room(bigint, boolean)', 'execute'),
        'relay must not call the ceiling helper directly';
    assert not has_function_privilege('sigylo_relay', 'access.ensure_room(bigint, boolean, bigint)', 'execute'),
        'relay must not call the ceiling helper directly';
    assert not has_function_privilege('sigylo_relay', 'access.registration_reserve_bytes()', 'execute'),
        'relay must not call the ceiling helper directly';
    assert not has_function_privilege('sigylo_relay', 'access.capacity_bytes()', 'execute'),
        'relay must not call the ceiling helper directly';
    assert not has_function_privilege('sigylo_relay', 'access.lifetime(integer)', 'execute'),
        'relay must only reach the documented functions';
    assert not has_schema_privilege('public', 'access', 'usage'),
        'PUBLIC must not use the access schema';
    assert (select bool_and(relrowsecurity and relforcerowsecurity) from pg_class
            where relnamespace = 'access'::regnamespace and relkind = 'r'),
        'RLS must be enabled and forced on every access table';
    assert not exists (
        select 1
        from (
            select coalesce(nspacl, acldefault('n', nspowner)) as acl, nspowner as owner
            from pg_namespace where nspname = 'access'
            union all
            select coalesce(relacl, acldefault('r', relowner)), relowner
            from pg_class where relnamespace = 'access'::regnamespace
            union all
            select coalesce(proacl, acldefault('f', proowner)), proowner
            from pg_proc where pronamespace = 'access'::regnamespace
        ) as objects, aclexplode(objects.acl) as grant_
        where grant_.grantee not in (objects.owner, 'sigylo_relay'::regrole)
    ), 'only the owner and sigylo_relay may hold privileges in the access schema';
    -- No username, e-mail, address or creation time can hide anywhere.
    assert (select count(*) from information_schema.columns where table_schema = 'access') = 17,
        'access tables must keep exactly the 17 documented columns';
end $$;
