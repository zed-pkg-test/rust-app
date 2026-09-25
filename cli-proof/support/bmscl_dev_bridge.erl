-module(bmscl_dev_bridge).

-export([main/0]).

-define(DEFAULT_DRAIN_MS, 30000).
-define(PREFIX, <<"BMSCL_DEV_JSON ">>).

main() ->
    process_flag(trap_exit, true),
    case start_runtime() of
        {ok, P1} ->
            reply(#{<<"ok">> => true,
                    <<"event">> => <<"ready">>,
                    <<"p1">> => pid_text(P1)}),
            loop(#{p1 => P1, deployments => #{}});
        {error, Reason} ->
            reply_error(Reason),
            halt(78)
    end.

loop(State0) ->
    case io:get_line(standard_io, "") of
        eof -> ok;
        {error, Reason} ->
            reply_error({stdin, Reason}),
            halt(74);
        Line ->
            case decode(Line) of
                {error, Reason} ->
                    reply_error(Reason),
                    loop(State0);
                {ok, Command} ->
                    case handle(Command, State0) of
                        {reply, Response, State1} ->
                            reply(Response),
                            loop(State1);
                        {stop, Response} ->
                            reply(Response),
                            ok
                    end
            end
    end.

handle(#{<<"cmd">> := <<"activate">>,
         <<"name">> := Name,
         <<"path">> := Path}, State0)
  when is_binary(Name), is_binary(Path) ->
    case bmscl_deployment_manager:activate_artifact(binary_to_list(Path)) of
        {ok, DeploymentId} ->
            Deployments0 = maps:get(deployments, State0),
            Entry = #{deployment_id => DeploymentId},
            State1 = State0#{deployments => maps:put(Name, Entry, Deployments0)},
            {reply, #{<<"ok">> => true,
                      <<"deployment_id">> => encode_term(DeploymentId)}, State1};
        {error, Reason} ->
            {reply, error_map({activate, Name, Reason}), State0}
    end;
handle(#{<<"cmd">> := <<"remove">>, <<"name">> := Name}, State0)
  when is_binary(Name) ->
    Deployments0 = maps:get(deployments, State0),
    State1 = State0#{deployments => maps:remove(Name, Deployments0)},
    {reply, #{<<"ok">> => true}, State1};
handle(#{<<"cmd">> := <<"publish">>, <<"version">> := Version}, State0)
  when is_integer(Version), Version > 0 ->
    Deployments = maps:get(deployments, State0),
    Routes = maps:fold(
        fun(Name, Entry, Acc) ->
            DeploymentId = maps:get(deployment_id, Entry),
            Key = {<<"ANY">>, route_path(Name)},
            Target = #{
                deployment_id => DeploymentId,
                actor_path => Name,
                entrypoint => <<"worker:handle/2">>
            },
            maps:put(Key, Target, Acc)
        end,
        #{}, Deployments),
    case bmscl_route_table:replace_snapshot(Version, Routes) of
        {ok, updated} -> {reply, #{<<"ok">> => true}, State0};
        {ok, unchanged} -> {reply, #{<<"ok">> => true}, State0};
        {error, Reason} -> {reply, error_map({route_publish, Reason}), State0}
    end;
handle(#{<<"cmd">> := <<"restart_p2">>}, State0) ->
    P1 = maps:get(p1, State0),
    case bmscl_runtime:restart(?DEFAULT_DRAIN_MS) of
        {ok, P2} when is_pid(P2) ->
            restart_reply(P1, P2, State0);
        {ok, P2, _Info} when is_pid(P2) ->
            restart_reply(P1, P2, State0);
        ok ->
            case whereis(bmscl_runtime_sup) of
                P2 when is_pid(P2) -> restart_reply(P1, P2, State0);
                _ -> {reply, error_map(p2_not_running_after_restart), State0}
            end;
        Error ->
            {reply, error_map({p2_restart, Error}), State0}
    end;
handle(#{<<"cmd">> := <<"health">>}, State0) ->
    P1 = whereis(bmscl_sup),
    P2 = whereis(bmscl_runtime_sup),
    Manager = whereis(bmscl_deployment_manager),
    Router = whereis(bmscl_route_table),
    Healthy = is_pid(P1) andalso is_pid(P2) andalso is_pid(Manager) andalso is_pid(Router),
    SameP1 = P1 =:= maps:get(p1, State0),
    {reply, #{<<"ok">> => Healthy andalso SameP1,
              <<"p1_stable">> => SameP1,
              <<"p1">> => pid_text(P1),
              <<"p2">> => pid_text(P2)}, State0};
handle(#{<<"cmd">> := <<"shutdown">>}, _State0) ->
    {stop, #{<<"ok">> => true}};
handle(Command, State0) ->
    {reply, error_map({unknown_command, Command}), State0}.

restart_reply(P1, P2, State0) ->
    case whereis(bmscl_sup) =:= P1 of
        true ->
            State1 = State0#{deployments => #{}},
            {reply, #{<<"ok">> => true,
                      <<"p1_stable">> => true,
                      <<"p2">> => pid_text(P2)}, State1};
        false ->
            {reply, error_map(p1_pid_changed), State0}
    end.

start_runtime() ->
    case ensure_loaded(bmscl_supervisor) of
        ok ->
            ok = application:set_env(bmscl_supervisor, require_attestation, false),
            ok = application:set_env(bmscl_supervisor, require_admission_receipt, false),
            ok = application:set_env(bmscl_supervisor, require_trusted_build_provenance, false),
            case application:ensure_all_started(bmscl_supervisor) of
                {ok, _} -> runtime_shape();
                {error, {already_started, _}} -> runtime_shape();
                {error, Reason} -> {error, {application_start, Reason}}
            end;
        Error -> Error
    end.

runtime_shape() ->
    case {whereis(bmscl_sup), whereis(bmscl_runtime_sup),
          whereis(bmscl_deployment_manager), whereis(bmscl_route_table)} of
        {P1, P2, Manager, Router}
          when is_pid(P1), is_pid(P2), is_pid(Manager), is_pid(Router) ->
            {ok, P1};
        Shape -> {error, {incomplete_supervision_shape, Shape}}
    end.

ensure_loaded(Application) ->
    case application:load(Application) of
        ok -> ok;
        {error, {already_loaded, Application}} -> ok;
        {error, Reason} -> {error, {application_load, Reason}}
    end.

route_path(<<"default">>) -> <<"/">>;
route_path(Name) ->
    Normalized = binary:replace(Name, <<"\\">>, <<"/">>, [global]),
    <<"/", (trim_leading_slashes(Normalized))/binary>>.

trim_leading_slashes(<<"/", Rest/binary>>) -> trim_leading_slashes(Rest);
trim_leading_slashes(Value) -> Value.

decode(Line0) ->
    Line = unicode:characters_to_binary(Line0),
    try jsx:decode(Line, [return_maps]) of
        Map when is_map(Map) -> {ok, Map};
        _ -> {error, invalid_command_json}
    catch
        _:_ -> {error, invalid_command_json}
    end.

reply(Map) ->
    Encoded = jsx:encode(Map),
    io:put_chars(standard_io, [?PREFIX, Encoded, <<"\n">>]).

reply_error(Reason) ->
    reply(error_map(Reason)).

error_map(Reason) ->
    #{<<"ok">> => false, <<"error">> => encode_term(Reason)}.

encode_term(Value) when is_binary(Value) -> Value;
encode_term(Value) when is_atom(Value) -> atom_to_binary(Value, utf8);
encode_term(Value) when is_integer(Value) -> Value;
encode_term(Value) -> unicode:characters_to_binary(io_lib:format("~p", [Value])).

pid_text(Pid) when is_pid(Pid) -> list_to_binary(pid_to_list(Pid));
pid_text(_) -> <<"undefined">>.
