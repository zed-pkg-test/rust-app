-module(bmscl_critical_section_actor).
-behaviour(gen_server).

-define(MAX_FENCING_SEQUENCE, 9007199254740991).

-export([start/1, start/2, acquire/3, acquire/4, renew/4, release/3, status/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Compatibility/test constructor. Production registry code uses start/2 with
%% an owner epoch allocated by the durable store.
start(RuntimeEpoch) when is_integer(RuntimeEpoch), RuntimeEpoch > 0 ->
    start(RuntimeEpoch, RuntimeEpoch);
start(_) ->
    {error, invalid_runtime_epoch}.

start(RuntimeEpoch, OwnerEpoch)
  when is_integer(RuntimeEpoch), RuntimeEpoch > 0,
       is_integer(OwnerEpoch), OwnerEpoch > 0 ->
    gen_server:start(?MODULE, {RuntimeEpoch, OwnerEpoch}, []);
start(RuntimeEpoch, Loaded)
  when is_integer(RuntimeEpoch), RuntimeEpoch > 0, is_map(Loaded) ->
    case maps:get(owner_epoch, Loaded, 0) of
        OwnerEpoch when is_integer(OwnerEpoch), OwnerEpoch > 0 ->
            gen_server:start(?MODULE, {RuntimeEpoch, Loaded}, []);
        _ ->
            {error, invalid_owner_epoch}
    end;
start(_, _) ->
    {error, invalid_owner_epoch}.

acquire(Pid, Holder, LeaseMs) when is_pid(Pid) ->
    acquire(Pid, Holder, undefined, LeaseMs);
acquire(_, _, _) ->
    {error, invalid_actor}.

acquire(Pid, Holder, RequestId, LeaseMs) when is_pid(Pid) ->
    gen_server:call(Pid, {acquire, Holder, RequestId, LeaseMs});
acquire(_, _, _, _) ->
    {error, invalid_actor}.

renew(Pid, Holder, Token, LeaseMs) when is_pid(Pid) ->
    gen_server:call(Pid, {renew, Holder, Token, LeaseMs});
renew(_, _, _, _) ->
    {error, invalid_actor}.

release(Pid, Holder, Token) when is_pid(Pid) ->
    gen_server:call(Pid, {release, Holder, Token});
release(_, _, _) ->
    {error, invalid_actor}.

status(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, status);
status(_) ->
    {error, invalid_actor}.

init({RuntimeEpoch, OwnerEpoch}) when is_integer(OwnerEpoch) ->
    {ok, #{runtime_epoch => RuntimeEpoch,
           owner_epoch => OwnerEpoch,
           sequence => 0,
           holder => undefined,
           request_id => undefined,
           expires_at_unix_ms => 0,
           persistent => false}};
init({RuntimeEpoch, Loaded}) when is_map(Loaded) ->
    Inherited = maps:get(holder, Loaded, undefined) =/= undefined
                andalso maps:get(expires_at_unix_ms, Loaded, 0) > now_unix_ms(),
    {ok, Loaded#{runtime_epoch => RuntimeEpoch,
                 persistent => true,
                 inherited_lease => Inherited}}.

handle_call({acquire, Holder, RequestId, LeaseMs}, _From, State0) ->
    case valid_holder(Holder)
         andalso valid_request_id(RequestId)
         andalso valid_lease_ms(LeaseMs) of
        false ->
            {reply, {error, invalid_acquire}, State0};
        true ->
            State = expire(State0),
            case maps:get(holder, State) of
                undefined ->
                    case maps:get(sequence, State) of
                        ?MAX_FENCING_SEQUENCE ->
                            {reply, {error, fencing_exhausted}, State};
                        Sequence0 ->
                            Sequence = Sequence0 + 1,
                            ExpiresAt = now_unix_ms() + LeaseMs,
                            Candidate = State#{sequence => Sequence,
                                              holder => Holder,
                                              request_id => RequestId,
                                              expires_at_unix_ms => ExpiresAt,
                                              inherited_lease => false},
                            case persist(Candidate) of
                                {ok, Next} -> {reply, {ok, grant(Next)}, Next};
                                {error, Reason} ->
                                    {reply, {error, {durable_commit_failed, Reason}}, State0}
                            end
                    end;
                Holder ->
                    Replay = RequestId =/= undefined
                             andalso RequestId =:= maps:get(request_id, State, undefined),
                    case {maps:get(inherited_lease, State, false), Replay} of
                        {false, true} -> {reply, {ok, grant(State)}, State};
                        _ -> {reply, {error, {busy, remaining_ms(State)}}, State}
                    end;
                _Other ->
                    {reply, {error, {busy, remaining_ms(State)}}, State}
            end
    end;
handle_call({renew, Holder, Token, LeaseMs}, _From, State0) ->
    case valid_holder(Holder) andalso valid_lease_ms(LeaseMs) of
        false ->
            {reply, {error, invalid_renew}, State0};
        true ->
            State = expire(State0),
            case owns(State, Holder, Token) of
                true ->
                    Candidate = State#{expires_at_unix_ms => now_unix_ms() + LeaseMs},
                    case persist(Candidate) of
                        {ok, Next} -> {reply, {ok, grant(Next)}, Next};
                        {error, Reason} ->
                            {reply, {error, {durable_commit_failed, Reason}}, State0}
                    end;
                false ->
                    {reply, {error, stale_or_not_owner}, State}
            end
    end;
handle_call({release, Holder, Token}, _From, State0) ->
    State = expire(State0),
    case owns(State, Holder, Token) of
        true ->
            Candidate = State#{holder => undefined,
                                request_id => undefined,
                                expires_at_unix_ms => 0},
            case persist(Candidate) of
                {ok, Next} -> {reply, ok, Next};
                {error, Reason} ->
                    {reply, {error, {durable_commit_failed, Reason}}, State0}
            end;
        false ->
            {reply, {error, stale_or_not_owner}, State}
    end;
handle_call(status, _From, State0) ->
    State = expire(State0),
    {reply, State#{remaining_ms => remaining_ms(State)}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_call}, State}.

handle_cast(_Message, State) -> {noreply, State}.
handle_info(_Message, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

grant(State) ->
    #{token => #{runtime_epoch => maps:get(runtime_epoch, State),
                 owner_epoch => maps:get(owner_epoch, State),
                 sequence => maps:get(sequence, State)},
      expires_at_ms => maps:get(expires_at_unix_ms, State)}.

owns(State, Holder, #{runtime_epoch := RuntimeEpoch,
                      owner_epoch := OwnerEpoch,
                      sequence := Sequence}) ->
    maps:get(holder, State) =:= Holder
    andalso maps:get(runtime_epoch, State) =:= RuntimeEpoch
    andalso maps:get(owner_epoch, State) =:= OwnerEpoch
    andalso maps:get(sequence, State) =:= Sequence
    andalso not maps:get(inherited_lease, State, false)
    andalso maps:get(expires_at_unix_ms, State) > now_unix_ms();
owns(_, _, _) -> false.

expire(State) ->
    case maps:get(holder, State) of
        undefined -> State;
        _ ->
            case maps:get(expires_at_unix_ms, State) =< now_unix_ms() of
                true -> State#{holder => undefined,
                                request_id => undefined,
                                expires_at_unix_ms => 0,
                                inherited_lease => false};
                false -> State
            end
    end.

remaining_ms(State) ->
    erlang:max(0, maps:get(expires_at_unix_ms, State) - now_unix_ms()).

valid_holder(Value) when is_binary(Value),
                         byte_size(Value) > 0,
                         byte_size(Value) =< 256 ->
    binary:match(Value, <<0>>) =:= nomatch;
valid_holder(_) -> false.

valid_request_id(undefined) -> true;
valid_request_id(Value) when is_binary(Value),
                             byte_size(Value) > 0,
                             byte_size(Value) =< 256 ->
    binary:match(Value, <<0>>) =:= nomatch;
valid_request_id(_) -> false.

valid_lease_ms(Value) when is_integer(Value), Value > 0 ->
    Max = application:get_env(bmscl_supervisor, critical_section_max_lease_ms, 300000),
    Value =< Max;
valid_lease_ms(_) -> false.

persist(State = #{persistent := false}) ->
    {ok, State};
persist(State = #{persistent := true,
                  store_module := Store,
                  identity := Identity,
                  owner_scope := Scope,
                  owner_epoch := OwnerEpoch}) ->
    bmscl_critical_section_store:commit(Store, Identity, Scope, OwnerEpoch, State).

now_unix_ms() -> erlang:system_time(millisecond).
