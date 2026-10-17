-- Run as the owner: checks the privilege layout the migration promises.
do $$
begin
    -- The relay may call the functions...
    assert has_function_privilege('sigylo_relay', 'custody.open(bytea)', 'execute'),
        'relay must be able to open';
    assert has_function_privilege('sigylo_relay', 'custody.purge_expired()', 'execute'),
        'relay must be able to purge';
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
    -- No column can hold plaintext metadata such as creation time or client address.
    assert (select count(*) from information_schema.columns where table_schema = 'custody') = 8,
        'custody tables must keep exactly the 8 documented columns';
end $$;
