-module(bmscl_critical_section_persistence_tests).
-include_lib("eunit/include/eunit.hrl").

restart_preserves_lease_and_fences_old_owner_test() ->
    bmscl_test_durable_store:reset(),
    application:set_env(
      bmscl_supervisor, durable_store_module, bmscl_test_durable_store),
    application:set_env(
      bmscl_supervisor, critical_section_max_lease_ms, 5000),

    {ok, Loaded1} = bmscl_critical_section_store:claim_and_load(
                      <<"tenant-a">>, <<"orders">>, <<"lock-1">>),
    ?assertEqual(1, maps:get(owner_epoch, Loaded1)),
    ?assertEqual(0, maps:get(version, Loaded1)),

    {ok, Pid1} = bmscl_critical_section_actor:start(100, Loaded1),
    {ok, Grant1} = bmscl_critical_section_actor:acquire(
                     Pid1, <<"holder-a">>, 1000),
    Token1 = maps:get(token, Grant1),
    ?assertEqual(1, maps:get(owner_epoch, Token1)),
    ?assertEqual(1, maps:get(sequence, Token1)),
    ok = gen_server:stop(Pid1),

    {ok, Loaded2} = bmscl_critical_section_store:claim_and_load(
                      <<"tenant-a">>, <<"orders">>, <<"lock-1">>),
    ?assertEqual(2, maps:get(owner_epoch, Loaded2)),
    ?assertEqual(1, maps:get(version, Loaded2)),
    ?assertEqual(<<"holder-a">>, maps:get(holder, Loaded2)),

    {ok, Pid2} = bmscl_critical_section_actor:start(101, Loaded2),
    ?assertMatch(
       {error, {busy, _}},
       bmscl_critical_section_actor:acquire(Pid2, <<"holder-a">>, 1000)),
    ?assertEqual(
       {error, stale_or_not_owner},
       bmscl_critical_section_actor:renew(
         Pid2, <<"holder-a">>, Token1, 1000)),
    ?assertEqual(
       {error, stale_or_not_owner},
       bmscl_critical_section_actor:release(
         Pid2, <<"holder-a">>, Token1)),
    ok = gen_server:stop(Pid2).

expired_inherited_lease_allows_new_fenced_grant_test() ->
    bmscl_test_durable_store:reset(),
    application:set_env(
      bmscl_supervisor, durable_store_module, bmscl_test_durable_store),
    application:set_env(
      bmscl_supervisor, critical_section_max_lease_ms, 5000),

    {ok, Loaded1} = bmscl_critical_section_store:claim_and_load(
                      <<"tenant-a">>, <<"orders">>, <<"lock-2">>),
    {ok, Pid1} = bmscl_critical_section_actor:start(200, Loaded1),
    {ok, _Grant1} = bmscl_critical_section_actor:acquire(
                      Pid1, <<"holder-a">>, 10),
    ok = gen_server:stop(Pid1),
    timer:sleep(25),

    {ok, Loaded2} = bmscl_critical_section_store:claim_and_load(
                      <<"tenant-a">>, <<"orders">>, <<"lock-2">>),
    {ok, Pid2} = bmscl_critical_section_actor:start(201, Loaded2),
    {ok, Grant2} = bmscl_critical_section_actor:acquire(
                     Pid2, <<"holder-b">>, 1000),
    Token2 = maps:get(token, Grant2),
    ?assertEqual(2, maps:get(owner_epoch, Token2)),
    ?assertEqual(2, maps:get(sequence, Token2)),
    ok = gen_server:stop(Pid2).

stale_store_owner_fails_commit_test() ->
    bmscl_test_durable_store:reset(),
    application:set_env(
      bmscl_supervisor, durable_store_module, bmscl_test_durable_store),

    {ok, Loaded1} = bmscl_critical_section_store:claim_and_load(
                      <<"tenant-a">>, <<"orders">>, <<"lock-3">>),
    {ok, Pid1} = bmscl_critical_section_actor:start(300, Loaded1),

    %% A second claimant fences Pid1 before it can publish a grant.
    {ok, _Loaded2} = bmscl_critical_section_store:claim_and_load(
                       <<"tenant-a">>, <<"orders">>, <<"lock-3">>),
    ?assertMatch(
       {error, {durable_commit_failed, {stale_owner_epoch, 2}}},
       bmscl_critical_section_actor:acquire(
         Pid1, <<"holder-a">>, 1000)),
    Status = bmscl_critical_section_actor:status(Pid1),
    ?assertEqual(undefined, maps:get(holder, Status)),
    ?assertEqual(0, maps:get(sequence, Status)),
    ok = gen_server:stop(Pid1).


same_request_id_replays_without_minting_or_extending_test() ->
    bmscl_test_durable_store:reset(),
    application:set_env(
      bmscl_supervisor, durable_store_module, bmscl_test_durable_store),
    application:set_env(
      bmscl_supervisor, critical_section_max_lease_ms, 5000),

    {ok, Loaded} = bmscl_critical_section_store:claim_and_load(
                     <<"tenant-a">>, <<"orders">>, <<"lock-replay">>),
    {ok, Pid} = bmscl_critical_section_actor:start(400, Loaded),
    {ok, Grant1} = bmscl_critical_section_actor:acquire(
                     Pid, <<"holder-a">>, <<"request-1">>, 1000),
    timer:sleep(5),
    {ok, Grant2} = bmscl_critical_section_actor:acquire(
                     Pid, <<"holder-a">>, <<"request-1">>, 1000),
    ?assertEqual(maps:get(token, Grant1), maps:get(token, Grant2)),
    ?assertEqual(maps:get(expires_at_ms, Grant1), maps:get(expires_at_ms, Grant2)),
    ?assertMatch(
       {error, {busy, _}},
       bmscl_critical_section_actor:acquire(
         Pid, <<"holder-a">>, <<"request-2">>, 1000)),
    ok = gen_server:stop(Pid).


fencing_sequence_exhaustion_fails_closed_test() ->
    Max = 9007199254740991,
    application:set_env(
      bmscl_supervisor, critical_section_max_lease_ms, 5000),
    {ok, Pid} = gen_server:start(
                  bmscl_critical_section_actor,
                  {500, #{owner_epoch => 7,
                          version => 1,
                          sequence => Max,
                          holder => undefined,
                          request_id => undefined,
                          expires_at_unix_ms => 0,
                          identity => #{},
                          owner_scope => #{},
                          store_module => bmscl_test_durable_store}},
                  []),
    ?assertEqual(
       {error, fencing_exhausted},
       bmscl_critical_section_actor:acquire(
         Pid, <<"holder-a">>, <<"request-max">>, 1000)),
    Status = bmscl_critical_section_actor:status(Pid),
    ?assertEqual(Max, maps:get(sequence, Status)),
    ?assertEqual(undefined, maps:get(holder, Status)),
    ok = gen_server:stop(Pid).
