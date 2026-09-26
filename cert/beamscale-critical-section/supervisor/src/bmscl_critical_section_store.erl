-module(bmscl_critical_section_store).

-export([claim_and_load/3, commit/5]).

-define(APPLICATION_ID, <<"critical-sections">>).
-define(SCHEMA, <<"bmscl.critical-section.state/v1">>).
-define(MAX_FENCING_SEQUENCE, 9007199254740991).

claim_and_load(Tenant, Namespace, ObjectKey) ->
    Store = store_module(),
    Scope = owner_scope(Tenant, Namespace, ObjectKey),
    Identity = identity(Tenant, Namespace, ObjectKey),
    case safe_call(Store, claim_owner, [Scope]) of
        {ok, OwnerEpoch} when is_integer(OwnerEpoch), OwnerEpoch > 0 ->
            case safe_call(Store, load, [Identity, Scope]) of
                {ok, not_found} ->
                    {ok, #{owner_epoch => OwnerEpoch,
                           version => 0,
                           sequence => 0,
                           holder => undefined,
                           request_id => undefined,
                           expires_at_unix_ms => 0,
                           identity => Identity,
                           owner_scope => Scope,
                           store_module => Store}};
                {ok, #{version := Version, state := Payload}}
                  when is_integer(Version), Version >= 0, is_binary(Payload) ->
                    case decode(Payload) of
                        {ok, Persisted} ->
                            {ok, Persisted#{
                                owner_epoch => OwnerEpoch,
                                version => Version,
                                identity => Identity,
                                owner_scope => Scope,
                                store_module => Store
                            }};
                        {error, Reason} ->
                            {error, {critical_section_state_decode_failed, Reason}}
                    end;
                {error, Reason} ->
                    {error, {critical_section_state_load_failed, Reason}};
                Other ->
                    {error, {invalid_critical_section_load_result, Other}}
            end;
        {error, Reason} ->
            {error, {critical_section_owner_claim_failed, Reason}};
        Other ->
            {error, {invalid_critical_section_owner_claim, Other}}
    end.

commit(Store, Identity, Scope, OwnerEpoch, #{version := Version} = State)
  when is_atom(Store), is_integer(OwnerEpoch), OwnerEpoch > 0,
       is_integer(Version), Version >= 0 ->
    Payload = encode(State),
    case safe_call(Store, commit,
                   [Identity, Version, Scope, OwnerEpoch, Payload]) of
        {ok, NextVersion} when is_integer(NextVersion), NextVersion =:= Version + 1 ->
            {ok, State#{version => NextVersion}};
        {ok, NextVersion} ->
            {error, {invalid_critical_section_next_version, NextVersion}};
        {error, Reason} ->
            {error, Reason};
        Other ->
            {error, {invalid_critical_section_commit_result, Other}}
    end.

identity(Tenant, Namespace, ObjectKey) ->
    #{tenant_id => Tenant,
      application_id => ?APPLICATION_ID,
      namespace => Namespace,
      object_key => ObjectKey}.

owner_scope(Tenant, Namespace, ObjectKey) ->
    Hash = crypto:hash(
             sha256,
             term_to_binary(
               {<<"bmscl-critical-section-v1">>, Tenant, Namespace, ObjectKey},
               [deterministic])),
    #{tenant_id => Tenant,
      application_id => ?APPLICATION_ID,
      namespace => Namespace,
      virtual_shard => binary:decode_unsigned(Hash)}.

store_module() ->
    application:get_env(
      bmscl_supervisor, durable_store_module, bmscl_durable_store_redis).

encode(State) ->
    Holder = nullable_binary(maps:get(holder, State, undefined)),
    RequestId = nullable_binary(maps:get(request_id, State, undefined)),
    jsx:encode(#{
        <<"schema">> => ?SCHEMA,
        <<"sequence">> => maps:get(sequence, State),
        <<"holder">> => Holder,
        <<"request_id">> => RequestId,
        <<"expires_at_unix_ms">> => maps:get(expires_at_unix_ms, State)
    }).

decode(Payload) ->
    try jsx:decode(Payload, [return_maps]) of
        #{<<"schema">> := ?SCHEMA,
          <<"sequence">> := Sequence,
          <<"holder">> := Holder0,
          <<"request_id">> := RequestId0,
          <<"expires_at_unix_ms">> := ExpiresAt}
          when is_integer(Sequence), Sequence >= 0,
               Sequence =< ?MAX_FENCING_SEQUENCE,
               is_integer(ExpiresAt), ExpiresAt >= 0 ->
            case {decode_bounded_optional(Holder0, 256),
                  decode_bounded_optional(RequestId0, 256)} of
                {{ok, Holder}, {ok, RequestId}} ->
                    {ok, #{sequence => Sequence,
                           holder => Holder,
                           request_id => RequestId,
                           expires_at_unix_ms => ExpiresAt}};
                {error, _} -> {error, invalid_holder};
                {_, error} -> {error, invalid_request_id}
            end;
        _ ->
            {error, invalid_payload}
    catch
        _:_ -> {error, invalid_json}
    end.

nullable_binary(undefined) -> null;
nullable_binary(Value) -> Value.

decode_bounded_optional(null, _Max) -> {ok, undefined};
decode_bounded_optional(Value, Max)
  when is_binary(Value), byte_size(Value) > 0, byte_size(Value) =< Max ->
    case binary:match(Value, <<0>>) of
        nomatch -> {ok, Value};
        _ -> error
    end;
decode_bounded_optional(_, _) -> error.

safe_call(Module, Function, Args) ->
    try apply(Module, Function, Args) of
        Result -> Result
    catch
        Class:Reason -> {error, {store_exception, Class, Reason}}
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

codec_round_trip_test() ->
    State = #{sequence => 7,
              holder => <<"holder-a">>,
              request_id => <<"request-1">>,
              expires_at_unix_ms => 123456,
              version => 4},
    ?assertEqual(
       {ok, #{sequence => 7,
              holder => <<"holder-a">>,
              request_id => <<"request-1">>,
              expires_at_unix_ms => 123456}},
       decode(encode(State))).

-endif.
