-module(bmscl_guest_control).
-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
    listen_socket,
    acceptor,
    artifact_root,
    connection_counter,
    max_connections,
    idle_timeout_ms
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    process_flag(trap_exit, true),
    Port = application:get_env(bmscl_supervisor, guest_control_port, 9101),
    MaxFrame = application:get_env(bmscl_supervisor, guest_control_max_frame_bytes, 16 * 1024 * 1024),
    MaxConnections = application:get_env(bmscl_supervisor, guest_control_max_connections, 64),
    IdleTimeout = application:get_env(bmscl_supervisor, guest_control_idle_timeout_ms, 30000),
    ArtifactRoot = application:get_env(
        bmscl_supervisor, guest_artifact_root, "/var/lib/beamscale/artifacts"),
    true = is_integer(Port) andalso Port > 0 andalso Port =< 65535,
    true = is_integer(MaxFrame) andalso MaxFrame >= 1024 andalso MaxFrame =< 64 * 1024 * 1024,
    true = is_integer(MaxConnections) andalso MaxConnections >= 1 andalso MaxConnections =< 4096,
    true = is_integer(IdleTimeout) andalso IdleTimeout >= 100 andalso IdleTimeout =< 300000,
    case bmscl_guest_artifact:artifact_path(
           ArtifactRoot,
           <<"0000000000000000000000000000000000000000000000000000000000000000">>) of
        {ok, _} -> ok;
        {error, RootReason} -> error({invalid_guest_artifact_root, RootReason})
    end,
    ListenOpts = [binary, {packet, 4}, {packet_size, MaxFrame}, {active, false},
                  {reuseaddr, true}, {ip, {127, 0, 0, 1}}, {backlog, 128},
                  {send_timeout, IdleTimeout}, {send_timeout_close, true}],
    Counter = atomics:new(1, [{signed, true}]),
    case gen_tcp:listen(Port, ListenOpts) of
        {ok, ListenSocket} ->
            Acceptor = spawn_link(
              fun() -> accept_loop(ListenSocket, ArtifactRoot, Counter,
                                   MaxConnections, IdleTimeout) end),
            {ok, #state{listen_socket = ListenSocket,
                        acceptor = Acceptor,
                        artifact_root = ArtifactRoot,
                        connection_counter = Counter,
                        max_connections = MaxConnections,
                        idle_timeout_ms = IdleTimeout}};
        {error, ListenReason} ->
            {stop, {guest_control_listen_failed, ListenReason}}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, unsupported}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason},
            State = #state{acceptor = Pid,
                           listen_socket = ListenSocket,
                           artifact_root = ArtifactRoot,
                           connection_counter = Counter,
                           max_connections = MaxConnections,
                           idle_timeout_ms = IdleTimeout}) ->
    case Reason of
        normal -> {noreply, State};
        shutdown -> {noreply, State};
        _ ->
            NewAcceptor = spawn_link(
              fun() -> accept_loop(ListenSocket, ArtifactRoot, Counter,
                                   MaxConnections, IdleTimeout) end),
            {noreply, State#state{acceptor = NewAcceptor}}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{listen_socket = ListenSocket}) ->
    _ = gen_tcp:close(ListenSocket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

accept_loop(ListenSocket, ArtifactRoot, Counter, MaxConnections, IdleTimeout) ->
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            Current = atomics:add_get(Counter, 1, 1),
            case Current =< MaxConnections of
                true ->
                    Worker = spawn(
                      fun() -> connection_worker(Counter, ArtifactRoot, IdleTimeout) end),
                    case gen_tcp:controlling_process(Socket, Worker) of
                        ok ->
                            Worker ! {serve, Socket};
                        {error, _} ->
                            _ = gen_tcp:close(Socket),
                            Worker ! stop
                    end;
                false ->
                    _ = atomics:add_get(Counter, 1, -1),
                    _ = gen_tcp:close(Socket)
            end,
            accept_loop(ListenSocket, ArtifactRoot, Counter,
                        MaxConnections, IdleTimeout);
        {error, closed} -> ok;
        {error, AcceptReason} -> exit({guest_control_accept_failed, AcceptReason})
    end.

connection_worker(Counter, ArtifactRoot, IdleTimeout) ->
    receive
        {serve, Socket} ->
            try serve_loop(Socket, ArtifactRoot, IdleTimeout)
            after
                _ = gen_tcp:close(Socket),
                _ = atomics:add_get(Counter, 1, -1)
            end;
        stop ->
            _ = atomics:add_get(Counter, 1, -1),
            ok
    after 5000 ->
        %% The acceptor failed after reserving a slot but before handoff.
        _ = atomics:add_get(Counter, 1, -1),
        ok
    end.

serve_loop(Socket, ArtifactRoot, IdleTimeout) ->
    case gen_tcp:recv(Socket, 0, IdleTimeout) of
        {ok, Frame} ->
            Reply = handle_frame(Frame, ArtifactRoot),
            case gen_tcp:send(Socket, Reply) of
                ok -> serve_loop(Socket, ArtifactRoot, IdleTimeout);
                {error, _} -> ok
            end;
        {error, closed} -> ok;
        {error, timeout} -> ok;
        {error, _} -> ok
    end.

handle_frame(Frame, ArtifactRoot) ->
    case bmscl_guest_protocol:decode_request(Frame) of
        {ok, #{op := invoke,
               invocation_id := InvocationId,
               deployment_id := DeploymentId,
               request := Request,
               context := Context,
               capability_refs := CapabilityRefs,
               timeout_ms := Timeout}} ->
            invoke_exact(InvocationId, DeploymentId, Request, Context, CapabilityRefs, Timeout);
        {ok, #{op := activate_artifact, deployment_id := DeploymentId}} ->
            activate_exact(ArtifactRoot, DeploymentId);
        {ok, #{op := critical_section,
               operation := Operation,
               tenant_id := TenantId,
               namespace := Namespace,
               object_key := ObjectKey,
               runtime_epoch := RuntimeEpoch,
               holder := Holder,
               request_id := RequestId,
               lease_ms := LeaseMs,
               token := Token}} ->
            critical_section_exact(
              Operation, TenantId, Namespace, ObjectKey,
              RuntimeEpoch, Holder, RequestId, LeaseMs, Token);
        {error, DecodeReason} ->
            bmscl_guest_protocol:encode_result(<<>>, {error, DecodeReason})
    end.

activate_exact(ArtifactRoot, DeploymentId) ->
    try bmscl_guest_artifact:activate(ArtifactRoot, DeploymentId) of
        ok -> bmscl_guest_protocol:encode_activation_result(DeploymentId, ok);
        {error, ActivateReason} ->
            bmscl_guest_protocol:encode_activation_result(DeploymentId, {error, ActivateReason})
    catch
        Class:CatchReason ->
            bmscl_guest_protocol:encode_activation_result(
              DeploymentId, {error, {artifact_activation_failed, Class, CatchReason}})
    end.

critical_section_exact(
  acquire, TenantId, Namespace, ObjectKey, RuntimeEpoch, Holder,
  RequestId, LeaseMs, _Token) ->
    Result = bmscl_critical_section_registry:acquire(
               TenantId, Namespace, ObjectKey, RuntimeEpoch,
               Holder, RequestId, LeaseMs),
    bmscl_guest_protocol:encode_critical_section_result(acquire, Result);
critical_section_exact(
  renew, TenantId, Namespace, ObjectKey, RuntimeEpoch, Holder,
  _RequestId, LeaseMs, Token) ->
    Result = bmscl_critical_section_registry:renew(
               TenantId, Namespace, ObjectKey, RuntimeEpoch, Holder, Token, LeaseMs),
    bmscl_guest_protocol:encode_critical_section_result(renew, Result);
critical_section_exact(
  release, TenantId, Namespace, ObjectKey, RuntimeEpoch, Holder,
  _RequestId, _LeaseMs, Token) ->
    Result = bmscl_critical_section_registry:release(
               TenantId, Namespace, ObjectKey, RuntimeEpoch, Holder, Token),
    bmscl_guest_protocol:encode_critical_section_result(release, Result).

invoke_exact(InvocationId, DeploymentId, Request, Context0, CapabilityRefs, Timeout) ->
    case bmscl_deployment_manager:pin_deployment(DeploymentId) of
        {ok, Pin} ->
            Grants = maps:get(capabilities, Pin, []),
            Allowed = bmscl_capability_scope:names(Grants),
            case bmscl_guest_protocol:validate_capability_refs(CapabilityRefs, Allowed) of
                ok ->
                    DeadlineUnixMs = erlang:system_time(millisecond) + Timeout,
                    WorkerContext = Context0#{
                        <<"invocation_id">> => InvocationId,
                        <<"root_invocation_id">> => InvocationId,
                        <<"call_depth">> => 0,
                        <<"deployment_id">> => DeploymentId,
                        <<"capability_refs">> => CapabilityRefs,
                        <<"admitted_capabilities">> => Allowed,
                        <<"admitted_capability_grants">> => Grants,
                        <<"deadline_unix_ms">> => DeadlineUnixMs,
                        <<"hosted_abi_version">> => bmscl_hosted_abi:version()
                    },
                    case bmscl_hosted_abi:validate_wire(Request, WorkerContext) of
                        ok -> dispatch_pinned(InvocationId, Pin, Request, WorkerContext, Timeout);
                        {error, AbiReason} ->
                            _ = bmscl_deployment_manager:release_pin(Pin),
                            bmscl_guest_protocol:encode_result(
                              InvocationId,
                              {error, {invalid_hosted_abi, AbiReason}},
                              #{termination_reason => invalid_hosted_abi})
                    end;
                {error, CapabilityReason} ->
                    _ = bmscl_deployment_manager:release_pin(Pin),
                    bmscl_guest_protocol:encode_result(
                      InvocationId,
                      {error, CapabilityReason},
                      #{termination_reason => capability_rejected})
            end;
        {error, PinReason} ->
            bmscl_guest_protocol:encode_result(
              InvocationId,
              {error, {deployment_pin_failed, PinReason}},
              #{termination_reason => deployment_pin_failed})
    end.

dispatch_pinned(InvocationId, Pin, Request, WorkerContext, Timeout) ->
    try bmscl_router:invoke_pinned_with_metrics(Pin, Request, WorkerContext, Timeout) of
        {Result, Metrics} ->
            bmscl_guest_protocol:encode_result(InvocationId, Result, Metrics)
    catch
        Class:DispatchReason ->
            _ = bmscl_deployment_manager:release_pin(Pin),
            bmscl_guest_protocol:encode_result(
              InvocationId,
              {error, {guest_dispatch_failed, Class, DispatchReason}},
              #{termination_reason => guest_dispatch_failed})
    end.
