-module(bmscl_critical_section_protocol_tests).
-include_lib("eunit/include/eunit.hrl").

acquire_accepts_null_token_with_request_id_test() ->
    Bytes = jsx:encode(#{
        <<"op">> => <<"critical_section">>,
        <<"operation">> => <<"acquire">>,
        <<"tenant_id">> => <<"tenant-a">>,
        <<"namespace">> => <<"orders">>,
        <<"object_key">> => <<"lock-1">>,
        <<"runtime_epoch">> => 9,
        <<"holder">> => <<"holder-a">>,
        <<"request_id">> => <<"request-1">>,
        <<"lease_ms">> => 1000,
        <<"token">> => null
    }),
    {ok, Decoded} = bmscl_guest_protocol:decode_request(Bytes),
    ?assertEqual(acquire, maps:get(operation, Decoded)),
    ?assertEqual(<<"request-1">>, maps:get(request_id, Decoded)),
    ?assertEqual(undefined, maps:get(token, Decoded)).

release_accepts_null_optional_fields_test() ->
    Bytes = jsx:encode(#{
        <<"op">> => <<"critical_section">>,
        <<"operation">> => <<"release">>,
        <<"tenant_id">> => <<"tenant-a">>,
        <<"namespace">> => <<"orders">>,
        <<"object_key">> => <<"lock-1">>,
        <<"runtime_epoch">> => 9,
        <<"holder">> => <<"holder-a">>,
        <<"request_id">> => null,
        <<"lease_ms">> => null,
        <<"token">> => #{
            <<"runtime_epoch">> => 9,
            <<"owner_epoch">> => 4,
            <<"sequence">> => 7
        }
    }),
    {ok, Decoded} = bmscl_guest_protocol:decode_request(Bytes),
    ?assertEqual(release, maps:get(operation, Decoded)),
    ?assertEqual(undefined, maps:get(request_id, Decoded)),
    ?assertEqual(undefined, maps:get(lease_ms, Decoded)).

acquire_requires_nonempty_request_id_test() ->
    Bytes = jsx:encode(#{
        <<"op">> => <<"critical_section">>,
        <<"operation">> => <<"acquire">>,
        <<"tenant_id">> => <<"tenant-a">>,
        <<"namespace">> => <<"orders">>,
        <<"object_key">> => <<"lock-1">>,
        <<"runtime_epoch">> => 9,
        <<"holder">> => <<"holder-a">>,
        <<"request_id">> => null,
        <<"lease_ms">> => 1000,
        <<"token">> => null
    }),
    ?assertEqual(
       {error, invalid_critical_section_envelope},
       bmscl_guest_protocol:decode_request(Bytes)).
