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
                         and column_name not in ('deposit_id', 'idx', 'object', 'size')),
        'custody.chunks and custody.garbage keep only object names and sizes';
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
    assert (select count(*) from information_schema.columns where table_schema = 'custody') = 16,
        'custody tables must keep exactly the 16 documented columns';
end $$;
