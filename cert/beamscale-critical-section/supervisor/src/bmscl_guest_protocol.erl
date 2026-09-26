-module(bmscl_guest_protocol).

-define(MAX_FENCING_SEQUENCE, 9007199254740991).

-export([
    decode_request/1,
    encode_result/2,
    encode_result/3,
    encode_activation_result/2,
    encode_critical_section_result/2,
    normalize_deployment_id/1,
    validate_capability_refs/2
]).

-spec decode_request(binary()) -> {ok, map()} | {error, term()}.
decode_request(Bytes) when is_binary(Bytes) ->
    try jsx:decode(Bytes, [return_maps]) of
        #{<<"op">> := <<"invoke">>,
          <<"deployment_id">> := DeploymentId0,
          <<"request">> := Request,
          <<"context">> := Context} = Envelope
          when is_binary(DeploymentId0), is_map(Request), is_map(Context) ->
            Timeout = maps:get(<<"timeout_ms">>, Envelope, 30000),
            InvocationId = maps:get(<<"invocation_id">>, Envelope, <<>>),
            DeploymentId = normalize_deployment_id(DeploymentId0),
            CapabilityRefs = normalize_capability_refs(
                maps:get(<<"capability_refs">>, Envelope, [])),
            case valid_timeout(Timeout) andalso
                 is_binary(InvocationId) andalso byte_size(InvocationId) =< 128 andalso
                 valid_deployment_id(DeploymentId) andalso
                 CapabilityRefs =/= error of
                true ->
                    {ok, #{
                        op => invoke,
                        invocation_id => InvocationId,
                        deployment_id => DeploymentId,
                        request => Request,
                        context => Context,
                        capability_refs => CapabilityRefs,
                        timeout_ms => Timeout
                    }};
                false -> {error, invalid_invocation_envelope}
            end;
        #{<<"op">> := <<"activate_artifact">>,
          <<"deployment_id">> := DeploymentId0}
          when is_binary(DeploymentId0) ->
            DeploymentId = normalize_deployment_id(DeploymentId0),
            case valid_deployment_id(DeploymentId) of
                true -> {ok, #{op => activate_artifact, deployment_id => DeploymentId}};
                false -> {error, invalid_activation_envelope}
            end;
        #{<<"op">> := <<"critical_section">>,
          <<"operation">> := Operation0,
          <<"tenant_id">> := TenantId,
          <<"namespace">> := Namespace,
          <<"object_key">> := ObjectKey,
          <<"runtime_epoch">> := RuntimeEpoch,
          <<"holder">> := Holder} = Envelope
          when is_binary(Operation0), is_binary(TenantId), is_binary(Namespace),
               is_binary(ObjectKey), is_integer(RuntimeEpoch), is_binary(Holder) ->
            case normalize_critical_operation(Operation0) of
                error ->
                    {error, invalid_critical_section_operation};
                Operation ->
                    LeaseMs = normalize_optional(
                                maps:get(<<"lease_ms">>, Envelope, undefined)),
                    RequestId = normalize_optional(
                                  maps:get(<<"request_id">>, Envelope, undefined)),
                    Token = normalize_critical_token(
                              normalize_optional(
                                maps:get(<<"token">>, Envelope, undefined))),
                    case valid_critical_identity(TenantId, Namespace, ObjectKey, Holder)
                         andalso RuntimeEpoch > 0
                         andalso valid_critical_arguments(
                                   Operation, LeaseMs, Token, RequestId) of
                        true ->
                            {ok, #{
                                op => critical_section,
                                operation => Operation,
                                tenant_id => TenantId,
                                namespace => Namespace,
                                object_key => ObjectKey,
                                runtime_epoch => RuntimeEpoch,
                                holder => Holder,
                                request_id => RequestId,
                                lease_ms => LeaseMs,
                                token => Token
                            }};
                        false ->
                            {error, invalid_critical_section_envelope}
                    end
            end;
        _ ->
            {error, invalid_invocation_envelope}
    catch
        _:_ -> {error, invalid_json}
    end;
decode_request(_) ->
    {error, invalid_frame}.

-spec encode_result(binary(), term()) -> binary().
encode_result(InvocationId, Result) ->
    encode_result(InvocationId, Result, #{}).

-spec encode_result(binary(), term(), map()) -> binary().
encode_result(InvocationId, {ok, Value}, Metrics) when is_binary(InvocationId), is_map(Metrics) ->
    Payload = term_to_binary(Value, [compressed]),
    jsx:encode(with_metrics(#{
        <<"invocation_id">> => InvocationId,
        <<"ok">> => true,
        <<"payload_encoding">> => <<"erlang_external_term_base64">>,
        <<"payload_etf_base64">> => base64:encode(Payload),
        <<"payload_etf_bytes">> => byte_size(Payload)
    }, Metrics));
encode_result(InvocationId, {error, Reason}, Metrics) when is_binary(InvocationId), is_map(Metrics) ->
    ErrorPayload = term_to_binary(Reason, [compressed]),
    jsx:encode(with_metrics(#{
        <<"invocation_id">> => InvocationId,
        <<"ok">> => false,
        <<"error_encoding">> => <<"erlang_external_term_base64">>,
        <<"error_etf_base64">> => base64:encode(ErrorPayload),
        <<"error_etf_bytes">> => byte_size(ErrorPayload)
    }, Metrics));
encode_result(InvocationId, Other, Metrics) when is_binary(InvocationId), is_map(Metrics) ->
    encode_result(InvocationId, {error, {invalid_router_result, Other}}, Metrics).

-spec encode_activation_result(binary(), ok | {error, term()}) -> binary().
encode_activation_result(DeploymentId, ok) when is_binary(DeploymentId) ->
    jsx:encode(#{
        <<"op">> => <<"activate_artifact_result">>,
        <<"ok">> => true,
        <<"deployment_id">> => DeploymentId,
        <<"active_deployment_id">> => DeploymentId
    });
encode_activation_result(DeploymentId, {error, Reason}) when is_binary(DeploymentId) ->
    jsx:encode(#{
        <<"op">> => <<"activate_artifact_result">>,
        <<"ok">> => false,
        <<"deployment_id">> => DeploymentId,
        <<"error_encoding">> => <<"erlang_external_term_base64">>,
        <<"error_etf_base64">> => base64:encode(term_to_binary(Reason, [compressed]))
    }).

-spec encode_critical_section_result(atom(), term()) -> binary().
encode_critical_section_result(Operation, {ok, Grant})
  when (Operation =:= acquire orelse Operation =:= renew), is_map(Grant) ->
    Token = maps:get(token, Grant),
    jsx:encode(#{
        <<"op">> => <<"critical_section_result">>,
        <<"operation">> => atom_to_binary(Operation, utf8),
        <<"ok">> => true,
        <<"token">> => #{
            <<"runtime_epoch">> => maps:get(runtime_epoch, Token),
            <<"owner_epoch">> => maps:get(owner_epoch, Token),
            <<"sequence">> => maps:get(sequence, Token)
        },
        <<"expires_at_ms">> => maps:get(expires_at_ms, Grant)
    });
encode_critical_section_result(release, ok) ->
    jsx:encode(#{
        <<"op">> => <<"critical_section_result">>,
        <<"operation">> => <<"release">>,
        <<"ok">> => true
    });
encode_critical_section_result(Operation, {error, {busy, RemainingMs}})
  when is_integer(RemainingMs), RemainingMs >= 0 ->
    jsx:encode(#{
        <<"op">> => <<"critical_section_result">>,
        <<"operation">> => atom_to_binary(Operation, utf8),
        <<"ok">> => false,
        <<"error_code">> => <<"busy">>,
        <<"remaining_ms">> => RemainingMs
    });
encode_critical_section_result(Operation, {error, stale_or_not_owner}) ->
    jsx:encode(#{
        <<"op">> => <<"critical_section_result">>,
        <<"operation">> => atom_to_binary(Operation, utf8),
        <<"ok">> => false,
        <<"error_code">> => <<"stale_or_not_owner">>
    });
encode_critical_section_result(Operation, {error, fencing_exhausted}) ->
    jsx:encode(#{
        <<"op">> => <<"critical_section_result">>,
        <<"operation">> => atom_to_binary(Operation, utf8),
        <<"ok">> => false,
        <<"error_code">> => <<"fencing_exhausted">>
    });
encode_critical_section_result(Operation, {error, Reason}) ->
    jsx:encode(#{
        <<"op">> => <<"critical_section_result">>,
        <<"operation">> => atom_to_binary(Operation, utf8),
        <<"ok">> => false,
        <<"error_code">> => <<"runtime_error">>,
        <<"error_etf_base64">> =>
            base64:encode(term_to_binary(Reason, [compressed]))
    });
encode_critical_section_result(Operation, Other) ->
    encode_critical_section_result(
      Operation, {error, {invalid_critical_section_result, Other}}).

-spec normalize_deployment_id(binary()) -> binary().
normalize_deployment_id(<<"sha256:", Digest/binary>>) -> Digest;
normalize_deployment_id(Digest) -> Digest.

-spec validate_capability_refs([map()], [binary()]) -> ok | {error, term()}.
validate_capability_refs(Refs, Allowed) when is_list(Refs), is_list(Allowed) ->
    Names = [maps:get(<<"name">>, Ref) || Ref <- Refs],
    case [Name || Name <- Names, not lists:member(Name, Allowed)] of
        [] -> ok;
        Denied -> {error, {capability_not_admitted, Denied}}
    end;
validate_capability_refs(_, _) ->
    {error, invalid_capability_refs}.

normalize_capability_refs(Refs) when is_list(Refs), length(Refs) =< 64 ->
    try
        Normalized = [normalize_capability_ref(Ref) || Ref <- Refs],
        Names = [maps:get(<<"name">>, Ref) || Ref <- Normalized],
        case length(Names) =:= length(lists:usort(Names)) of
            true -> Normalized;
            false -> error
        end
    catch
        _:_ -> error
    end;
normalize_capability_refs(_) -> error.

normalize_capability_ref(#{<<"name">> := Name, <<"token_ref">> := TokenRef})
  when is_binary(Name), is_binary(TokenRef),
       byte_size(Name) > 4, byte_size(Name) =< 128,
       byte_size(TokenRef) > 0, byte_size(TokenRef) =< 256 ->
    case re:run(Name, <<"^ctx\\.[a-zA-Z0-9._-]+$">>, [{capture, none}]) of
        match -> #{<<"name">> => Name, <<"token_ref">> => TokenRef};
        nomatch -> error(invalid_capability_name)
    end;
normalize_capability_ref(_) -> error(invalid_capability_ref).

with_metrics(Response, Metrics) ->
    Response#{
        <<"wall_time_ms">> => nonnegative_metric(wall_time_ms, Metrics),
        <<"reductions">> => nonnegative_metric(reductions, Metrics),
        <<"output_bytes">> => nonnegative_metric(output_bytes, Metrics),
        <<"executed_digest">> => executed_digest(Metrics),
        <<"termination_reason">> => termination_reason(Metrics)
    }.

nonnegative_metric(Key, Metrics) ->
    case maps:get(Key, Metrics, 0) of
        Value when is_integer(Value), Value >= 0 -> Value;
        _ -> 0
    end.

executed_digest(Metrics) ->
    case maps:get(executed_digest, Metrics, <<>>) of
        Value when is_binary(Value), byte_size(Value) =:= 64 ->
            case valid_deployment_id(Value) of
                true -> Value;
                false -> <<>>
            end;
        _ -> <<>>
    end.

termination_reason(Metrics) ->
    case maps:get(termination_reason, Metrics, normal) of
        Value when is_atom(Value) -> atom_to_binary(Value, utf8);
        Value when is_binary(Value) -> Value;
        _ -> <<"unknown">>
    end.

normalize_critical_operation(<<"acquire">>) -> acquire;
normalize_critical_operation(<<"renew">>) -> renew;
normalize_critical_operation(<<"release">>) -> release;
normalize_critical_operation(_) -> error.

normalize_optional(null) -> undefined;
normalize_optional(undefined) -> undefined;
normalize_optional(Value) -> Value.

normalize_critical_token(undefined) -> undefined;
normalize_critical_token(#{
    <<"runtime_epoch">> := RuntimeEpoch,
    <<"owner_epoch">> := OwnerEpoch,
    <<"sequence">> := Sequence
}) when is_integer(RuntimeEpoch), RuntimeEpoch > 0,
        is_integer(OwnerEpoch), OwnerEpoch > 0,
        is_integer(Sequence), Sequence > 0,
        Sequence =< ?MAX_FENCING_SEQUENCE ->
    #{runtime_epoch => RuntimeEpoch, owner_epoch => OwnerEpoch, sequence => Sequence};
normalize_critical_token(_) -> error.

valid_critical_arguments(acquire, LeaseMs, undefined, RequestId) ->
    valid_critical_lease(LeaseMs) andalso valid_request_id(RequestId);
valid_critical_arguments(renew, LeaseMs, Token, undefined) ->
    valid_critical_lease(LeaseMs) andalso is_map(Token);
valid_critical_arguments(release, undefined, Token, undefined) ->
    is_map(Token);
valid_critical_arguments(_, _, _, _) ->
    false.

valid_request_id(Value) when is_binary(Value),
                             byte_size(Value) > 0,
                             byte_size(Value) =< 256 ->
    binary:match(Value, <<0>>) =:= nomatch;
valid_request_id(_) -> false.

valid_critical_lease(Value) ->
    is_integer(Value) andalso Value > 0 andalso Value =< 300000.

valid_critical_identity(TenantId, Namespace, ObjectKey, Holder) ->
    valid_bounded_binary(TenantId, 1024)
    andalso valid_namespace(Namespace)
    andalso valid_bounded_binary(ObjectKey, 4096)
    andalso valid_bounded_binary(Holder, 256).

valid_namespace(Value) when is_binary(Value), byte_size(Value) > 0,
                           byte_size(Value) =< 128 ->
    re:run(Value, <<"^[A-Za-z0-9._-]+$">>, [{capture, none}]) =:= match;
valid_namespace(_) -> false.

valid_bounded_binary(Value, Max) when is_binary(Value), byte_size(Value) > 0,
                                      byte_size(Value) =< Max ->
    binary:match(Value, <<0>>) =:= nomatch;
valid_bounded_binary(_, _) -> false.

valid_timeout(Timeout) ->
    is_integer(Timeout) andalso Timeout > 0 andalso
    Timeout =< bmscl_limits:platform_max_wall_ms().

valid_deployment_id(Digest) when is_binary(Digest), byte_size(Digest) =:= 64 ->
    re:run(Digest, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
valid_deployment_id(_) -> false.
