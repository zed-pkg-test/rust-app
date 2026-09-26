-module(bmscl_critical_section_tests).
-include_lib("eunit/include/eunit.hrl").

fencing_sequence_and_epoch_test() ->
    application:set_env(bmscl_supervisor, critical_section_max_lease_ms, 5000),
    {ok, Pid} = bmscl_critical_section_actor:start(41),
    {ok, Grant1} = bmscl_critical_section_actor:acquire(Pid, <<"a">>, 1000),
    Token1 = maps:get(token, Grant1),
    ?assertEqual(#{runtime_epoch => 41, owner_epoch => 41, sequence => 1}, Token1),
    ?assertMatch({error, {busy, _}},
                 bmscl_critical_section_actor:acquire(Pid, <<"b">>, 1000)),
    ?assertEqual({error, stale_or_not_owner},
                 bmscl_critical_section_actor:release(Pid, <<"b">>, Token1)),
    ok = bmscl_critical_section_actor:release(Pid, <<"a">>, Token1),
    {ok, Grant2} = bmscl_critical_section_actor:acquire(Pid, <<"b">>, 1000),
    ?assertEqual(
       #{runtime_epoch => 41, owner_epoch => 41, sequence => 2},
       maps:get(token, Grant2)),
    ok = gen_server:stop(Pid).

tenancy_policy_test() ->
    ?assertEqual(mixed_tenants, bmscl_tenancy_policy:class(lambda_free_v1)),
    ?assertEqual(tenant_dedicated, bmscl_tenancy_policy:class(lambda_pro_v1)),
    ?assertEqual(tenant_dedicated, bmscl_tenancy_policy:class(durable_actor_v1)),
    ?assertEqual(tenant_dedicated, bmscl_tenancy_policy:class(critical_section_v1)),
    ?assertEqual(ok, bmscl_tenancy_policy:validate(durable_actor_v1, tenant_dedicated)),
    ?assertMatch({error, {tenancy_class_mismatch, tenant_dedicated, mixed_tenants}},
                 bmscl_tenancy_policy:validate(durable_actor_v1, mixed_tenants)).
