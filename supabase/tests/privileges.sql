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
    -- ...but has no table privilege at all.
    assert not has_table_privilege('sigylo_relay', 'custody.deposits', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.deposits directly';
    assert not has_table_privilege('sigylo_relay', 'custody.requests', 'select,insert,update,delete,truncate'),
        'relay must not touch custody.requests directly';
    -- PUBLIC (and therefore Supabase anon/authenticated) gets nothing.
    assert not has_function_privilege('public', 'custody.open(bytea)', 'execute'),
        'PUBLIC must not execute custody functions';
    assert not has_schema_privilege('public', 'custody', 'usage'),
        'PUBLIC must not use the custody schema';
    assert (select relrowsecurity and relforcerowsecurity from pg_class where oid = 'custody.deposits'::regclass),
        'RLS must be enabled and forced on deposits';
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
    assert (select count(*) from information_schema.columns where table_schema = 'custody') = 9,
        'custody tables must keep exactly the 9 documented columns';
end $$;
