-module(bmscl_artifact).

-export([verify/1, verify_provenance/2]).

-define(PROFILE_V2, <<"bmscl-hosted-gleam-v2-read-only">>).
-define(PROFILE_V3_HTTP, <<"bmscl-hosted-gleam-v3-http-capability">>).
-define(PROFILE_DURABLE_V1, <<"bmscl-hosted-gleam-durable-actor-v1">>).
-define(PROFILE_CRITICAL_ERLANG_V1, <<"bmscl-critical-section-erlang-v1">>).
-define(LEGACY_PROFILE, <<"bmscl-hosted-gleam-v1">>).
-define(ENTRYPOINT, <<"worker:handle/2">>).
-define(PROVENANCE_FORMAT, <<"bmscl-build-provenance-v1">>).
-define(MODULE_CONTRACT_V1, <<"bmscl-module-contract-v1">>).
-define(CONTEXT_ABI_V1, <<"bmscl.context/v1">>).

-spec verify(file:filename_all()) -> {ok, map()} | {error, term()}.
verify(ArtifactDir0) ->
    ArtifactDir = filename:absname(ArtifactDir0),
    try
        ManifestPath = filename:join(ArtifactDir, "manifest.json"),
        AdmissionPath = filename:join(ArtifactDir, "admission-report.json"),
        ManifestBytes = read_required_file(ManifestPath),
        AdmissionBytes = read_required_file(AdmissionPath),
        ok = bmscl_attestation:verify(ArtifactDir, ManifestBytes, AdmissionBytes),
        Manifest = decode_json_bytes(ManifestPath, ManifestBytes),
        Admission = decode_json_bytes(AdmissionPath, AdmissionBytes),
        ok = verify_manifest(Manifest),
        ok = verify_admission(Manifest, Admission),
        Provenance = verify_artifact_provenance(ArtifactDir, Manifest),
        BeamDir = filename:join(ArtifactDir, "beam"),
        {ok, ModuleFiles} = read_beams(BeamDir),
        %% Preserve the existing signed-artifact error contract: integrity of
        %% the exact BEAM bytes is checked before structural admission. The atom
        %% gate still runs strictly before any tenant code can be loaded.
        ok = verify_build_digest(Manifest, ModuleFiles),
        {ok, StaticAtomCount} = bmscl_beam_static_limits:verify(ModuleFiles),
        Names = [Name || {Name, _Path, _Bin} <- ModuleFiles],
        ok = verify_module_names(Names),
        ok = verify_trusted_sdk_modules(Names, Provenance),
        true = lists:member(<<"worker">>, Names),
        Limits = normalize_limits(maps:get(<<"runtime_limits">>, Manifest)),
        Capabilities = normalize_capabilities(maps:get(<<"capabilities">>, Manifest, [])),
        Profile = maps:get(<<"profile">>, Manifest),
        Durable = normalize_durable(Profile, maps:get(<<"durable">>, Manifest, undefined)),
        {ok, #{
            deployment_id => maps:get(<<"build_sha256">>, Manifest),
            source_sha256 => maps:get(<<"source_sha256">>, Manifest),
            module_files => ModuleFiles,
            module_names => Names,
            static_atom_count => StaticAtomCount,
            entrypoint_module => <<"worker">>,
            entrypoint_function => handle,
            runtime_limits => Limits,
            capabilities => Capabilities,
            profile => Profile,
            durable => Durable,
            provenance => Provenance,
            manifest => Manifest
        }}
    catch
        error:{badmatch, false} -> {error, missing_worker_entrypoint};
        error:{badmatch, {error, Reason}} -> {error, Reason};
        error:{badkey, Key} -> {error, {missing_manifest_key, Key}};
        error:Reason -> {error, Reason};
        throw:Reason -> {error, Reason}
    end.

read_required_file(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> error({artifact_file_read_failed, Path, Reason})
    end.

decode_json_bytes(Path, Bytes) ->
    try jsx:decode(Bytes, [return_maps])
    catch _:_ -> error({invalid_json, Path})
    end.

verify_manifest(M) ->
    Version = maps:get(<<"format_version">>, M),
    Require = application:get_env(bmscl_supervisor, require_attestation, true),
    case {Require, Version} of
        {true, 2} -> ok;
        {true, _} -> error({legacy_artifact_forbidden, Version});
        {false, 1} -> ok;
        {false, 2} -> ok;
        {false, _} -> error({unsupported_artifact_format, Version})
    end,
    require_equal(runtime, <<"beam">>, maps:get(<<"runtime">>, M)),
    Language = maps:get(<<"language">>, M),
    Profile = maps:get(<<"profile">>, M),
    require_language_profile(Language, Profile),
    require_profile(Profile),
    ok = verify_module_context_contract(Version, M),
    _Durable = normalize_durable(Profile, maps:get(<<"durable">>, M, undefined)),
    require_equal(entrypoint, ?ENTRYPOINT, maps:get(<<"entrypoint">>, M)),
    Source = maps:get(<<"source_sha256">>, M),
    Build = maps:get(<<"build_sha256">>, M),
    true = valid_sha256(Source),
    true = valid_sha256(Build),
    case Version of
        2 -> true = valid_sha256(maps:get(<<"provenance_sha256">>, M));
        1 -> ok
    end,
    Limits = normalize_limits(maps:get(<<"runtime_limits">>, M)),
    require_equal(max_processes, 1, maps:get(max_processes, Limits)),
    ok = bmscl_limits:validate_runtime_limits(Limits),
    Capabilities = normalize_capabilities(maps:get(<<"capabilities">>, M, [])),
    CapabilityNames = lists:sort(bmscl_capability_scope:names(Capabilities)),
    require_capabilities(Profile, CapabilityNames),
    ok.

verify_module_context_contract(1, _Manifest) ->
    ok;
verify_module_context_contract(2, Manifest) ->
    Contract = maps:get(<<"module_contract_version">>, Manifest, undefined),
    ContextAbi = maps:get(<<"context_abi">>, Manifest, undefined),
    Require = application:get_env(
                bmscl_supervisor, require_module_context_contract, false),
    case {Contract, ContextAbi, Require} of
        {?MODULE_CONTRACT_V1, ?CONTEXT_ABI_V1, _} -> ok;
        {undefined, undefined, false} -> ok;
        {undefined, undefined, true} -> error(missing_module_context_contract);
        {undefined, _, _} -> error(partial_module_context_contract);
        {_, undefined, _} -> error(partial_module_context_contract);
        _ -> error({unsupported_module_context_contract, Contract, ContextAbi})
    end.

require_language_profile(<<"gleam">>, ?PROFILE_V2) -> ok;
require_language_profile(<<"gleam">>, ?PROFILE_V3_HTTP) -> ok;
require_language_profile(<<"gleam">>, ?PROFILE_DURABLE_V1) -> ok;
require_language_profile(<<"gleam">>, ?LEGACY_PROFILE) -> ok;
require_language_profile(<<"erlang">>, ?PROFILE_CRITICAL_ERLANG_V1) -> ok;
require_language_profile(Language, Profile) ->
    error({unsupported_language_profile, Language, Profile}).

require_profile(?PROFILE_V2) -> ok;
require_profile(?PROFILE_V3_HTTP) -> ok;
require_profile(?PROFILE_DURABLE_V1) -> ok;
require_profile(?PROFILE_CRITICAL_ERLANG_V1) -> ok;
require_profile(?LEGACY_PROFILE) ->
    case legacy_dev_artifact_allowed() of
        true -> ok;
        false -> require_equal(profile, ?PROFILE_V2, ?LEGACY_PROFILE)
    end;
require_profile(Actual) ->
    error({unsupported_hosted_profile, Actual}).

require_capabilities(?PROFILE_V2, CapabilityNames) ->
    require_equal(capability_names,
                  lists:sort([<<"ctx.cluster">>, <<"ctx.log">>]), CapabilityNames);
require_capabilities(?PROFILE_V3_HTTP, CapabilityNames) ->
    require_equal(capability_names,
                  lists:sort([<<"ctx.cluster">>, <<"ctx.http">>, <<"ctx.log">>]),
                  CapabilityNames);
require_capabilities(?PROFILE_DURABLE_V1, CapabilityNames) ->
    require_equal(capability_names,
                  lists:sort([<<"ctx.cluster">>, <<"ctx.log">>]), CapabilityNames);
require_capabilities(?PROFILE_CRITICAL_ERLANG_V1, CapabilityNames) ->
    require_equal(capability_names,
                  lists:sort([<<"ctx.cluster">>, <<"ctx.log">>]), CapabilityNames);
require_capabilities(?LEGACY_PROFILE, CapabilityNames) ->
    true = legacy_dev_artifact_allowed(),
    require_equal(capability_names, [], CapabilityNames).

legacy_dev_artifact_allowed() ->
    application:get_env(bmscl_supervisor, require_admission_receipt, true) =:= false andalso
    application:get_env(bmscl_supervisor, require_attestation, true) =:= false andalso
    application:get_env(bmscl_supervisor, require_trusted_build_provenance, true) =:= false.

verify_admission(M, A) ->
    require_equal(admitted, true, maps:get(<<"admitted">>, A)),
    Profile = maps:get(<<"profile">>, M),
    require_equal(policy_version, Profile, maps:get(<<"policy_version">>, A)),
    require_equal(source_sha256, maps:get(<<"source_sha256">>, M), maps:get(<<"source_sha256">>, A)),
    require_equal(runtime_limits,
                  normalize_limits(maps:get(<<"runtime_limits">>, M)),
                  normalize_limits(maps:get(<<"runtime_limits">>, A))),
    require_equal(durable,
                  normalize_durable(Profile, maps:get(<<"durable">>, M, undefined)),
                  normalize_durable(Profile, maps:get(<<"durable">>, A, undefined))),
    ok.

verify_artifact_provenance(ArtifactDir, Manifest) ->
    case maps:get(<<"format_version">>, Manifest) of
        1 -> undefined;
        2 ->
            Path = filename:join(ArtifactDir, "provenance.json"),
            Bytes = read_required_file(Path),
            Expected = maps:get(<<"provenance_sha256">>, Manifest),
            require_equal(provenance_sha256, Expected, sha256_hex(Bytes)),
            Provenance = decode_json_bytes(Path, Bytes),
            ok = verify_provenance(Manifest, Provenance),
            Provenance
    end.

-spec verify_provenance(map(), map()) -> ok | no_return().
verify_provenance(Manifest, Provenance) ->
    require_equal(provenance_format, ?PROVENANCE_FORMAT,
                  maps:get(<<"format">>, Provenance)),
    require_equal(provenance_source_sha256,
                  maps:get(<<"source_sha256">>, Manifest),
                  maps:get(<<"source_sha256">>, Provenance)),
    require_equal(provenance_build_sha256,
                  maps:get(<<"build_sha256">>, Manifest),
                  maps:get(<<"build_sha256">>, Provenance)),
    BuilderId = maps:get(<<"builder_id">>, Provenance),
    BuilderImage = maps:get(<<"builder_image_digest">>, Provenance),
    CompilerVersion = maps:get(<<"compiler_version">>, Provenance),
    CompilerRevision = maps:get(<<"compiler_revision">>, Provenance),
    GleamVersion = maps:get(<<"gleam_version">>, Provenance),
    OtpRelease = maps:get(<<"otp_release">>, Provenance),
    ErtsVersion = maps:get(<<"erts_version">>, Provenance),
    PolicySha = maps:get(<<"policy_sha256">>, Provenance),
    DependencyLockSha = maps:get(<<"dependency_lock_sha256">>, Provenance, null),
    TrustedSdkSha = maps:get(<<"trusted_sdk_sha256">>, Provenance, null),
    true = valid_identifier(BuilderId),
    true = valid_image_digest(BuilderImage),
    true = valid_tool_version(CompilerVersion),
    true = valid_git_revision(CompilerRevision),
    true = valid_tool_version(GleamVersion),
    true = valid_tool_version(OtpRelease),
    true = valid_tool_version(ErtsVersion),
    true = valid_sha256(PolicySha),
    true = valid_optional_sha256(DependencyLockSha),
    true = valid_optional_sha256(TrustedSdkSha),
    RequireTrustedBuild = application:get_env(
        bmscl_supervisor,
        require_trusted_build_provenance,
        application:get_env(bmscl_supervisor, require_attestation, true)),
    case RequireTrustedBuild of
        true ->
            require_trusted(builder_id, BuilderId, trusted_builder_ids),
            require_trusted(builder_image_digest, BuilderImage, trusted_builder_image_digests),
            require_trusted(policy_sha256, PolicySha, trusted_policy_sha256),
            require_trusted(compiler_revision, CompilerRevision, trusted_compiler_revisions),
            case maps:get(<<"language">>, Manifest) of
                <<"gleam">> ->
                    require_trusted(gleam_version, GleamVersion, trusted_gleam_versions);
                <<"erlang">> ->
                    ok
            end,
            require_trusted(otp_release, OtpRelease, trusted_otp_releases),
            require_trusted(erts_version, ErtsVersion, trusted_erts_versions),
            case TrustedSdkSha of
                null -> ok;
                _ -> require_trusted(trusted_sdk_sha256, TrustedSdkSha, trusted_sdk_sha256)
            end;
        false -> ok
    end,
    ok.

require_trusted(Field, Value, EnvKey) ->
    Configured = application:get_env(bmscl_supervisor, EnvKey, []),
    case is_list(Configured) andalso
         lists:member(Value, [normalize_binary(V) || V <- Configured]) of
        true -> ok;
        false -> error({untrusted_provenance, Field, Value})
    end.

normalize_limits(L) ->
    Wall = positive_integer(max_wall_ms, maps:get(<<"max_wall_ms">>, L)),
    Reductions = positive_integer(max_reductions, maps:get(<<"max_reductions">>, L)),
    Heap = positive_integer(max_heap_bytes, maps:get(<<"max_heap_bytes">>, L)),
    Processes = positive_integer(max_processes, maps:get(<<"max_processes">>, L)),
    #{max_wall_ms => Wall,
      max_reductions => Reductions,
      max_heap_bytes => Heap,
      max_processes => Processes}.

normalize_capabilities(Capabilities) ->
    bmscl_capability_scope:normalize_grants(Capabilities).

normalize_durable(?PROFILE_DURABLE_V1, Durable) when is_map(Durable) ->
    Namespace = maps:get(<<"namespace">>, Durable),
    case valid_durable_namespace(Namespace) of
        true -> ok;
        false -> error({invalid_durable_namespace, Namespace})
    end,
    VirtualShards = bounded_integer(
                      virtual_shards, maps:get(<<"virtual_shards">>, Durable), 64, 65536),
    ShardsPerActor = bounded_integer(
                       shards_per_actor, maps:get(<<"shards_per_actor">>, Durable), 1, 4096),
    case ShardsPerActor =< VirtualShards
         andalso VirtualShards rem ShardsPerActor =:= 0 of
        true ->
            #{namespace => Namespace,
              virtual_shards => VirtualShards,
              shards_per_actor => ShardsPerActor};
        false ->
            error({invalid_durable_shard_layout, VirtualShards, ShardsPerActor})
    end;
normalize_durable(?PROFILE_DURABLE_V1, Value) ->
    error({invalid_durable_config, Value});
normalize_durable(_Profile, undefined) -> undefined;
normalize_durable(_Profile, null) -> undefined;
normalize_durable(Profile, Value) ->
    error({durable_config_forbidden, Profile, Value}).

valid_durable_namespace(Value) when is_binary(Value),
                                    byte_size(Value) >= 1,
                                    byte_size(Value) =< 128 ->
    re:run(Value, <<"^[A-Za-z0-9._-]+$">>, [{capture, none}]) =:= match;
valid_durable_namespace(_) -> false.

bounded_integer(_Name, V, Min, Max)
  when is_integer(V), V >= Min, V =< Max -> V;
bounded_integer(Name, V, Min, Max) ->
    error({invalid_bounded_integer, Name, V, Min, Max}).

positive_integer(_Name, V) when is_integer(V), V > 0 -> V;
positive_integer(Name, V) -> error({invalid_positive_limit, Name, V}).

require_equal(_Name, V, V) -> ok;
require_equal(Name, Expected, Actual) -> error({artifact_contract_mismatch, Name, Expected, Actual}).

valid_sha256(B) when is_binary(B), byte_size(B) =:= 64 ->
    re:run(B, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
valid_sha256(_) -> false.
valid_optional_sha256(null) -> true;
valid_optional_sha256(Value) -> valid_sha256(Value).
valid_identifier(B) when is_binary(B), byte_size(B) >= 1, byte_size(B) =< 128 ->
    re:run(B, <<"^[A-Za-z0-9._:/-]+$">>, [{capture, none}]) =:= match;
valid_identifier(_) -> false.
valid_image_digest(B) when is_binary(B) ->
    re:run(B, <<"^sha256:[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
valid_image_digest(_) -> false.
valid_git_revision(B) when is_binary(B) ->
    re:run(B, <<"^[0-9a-f]{40,64}$">>, [{capture, none}]) =:= match;
valid_git_revision(_) -> false.
valid_tool_version(B) when is_binary(B), byte_size(B) >= 1, byte_size(B) =< 64 ->
    re:run(B, <<"^[A-Za-z0-9._+:-]+$">>, [{capture, none}]) =:= match;
valid_tool_version(_) -> false.

read_beams(BeamDir) ->
    case file:list_dir(BeamDir) of
        {ok, Entries0} ->
            Entries = lists:sort([E || E <- Entries0, filename:extension(E) =:= ".beam"]),
            case Entries of
                [] -> {error, no_beam_modules};
                _ -> read_beams(BeamDir, Entries, [])
            end;
        {error, Reason} -> {error, {beam_dir_read_failed, BeamDir, Reason}}
    end.
read_beams(_Dir, [], Acc) -> {ok, lists:reverse(Acc)};
read_beams(Dir, [File | Rest], Acc) ->
    Path = filename:join(Dir, File),
    case file:read_file(Path) of
        {ok, Bin} ->
            Name = unicode:characters_to_binary(filename:rootname(File, ".beam")),
            read_beams(Dir, Rest, [{Name, Path, Bin} | Acc]);
        {error, Reason} -> {error, {beam_read_failed, Path, Reason}}
    end.

verify_build_digest(Manifest, ModuleFiles) ->
    Ctx0 = crypto:hash_init(sha256),
    Ctx = lists:foldl(
      fun({Name, _Path, Bin}, C0) ->
          Filename = <<Name/binary, ".beam">>,
          C1 = crypto:hash_update(C0, Filename),
          C2 = crypto:hash_update(C1, <<0>>),
          C3 = crypto:hash_update(C2, Bin),
          crypto:hash_update(C3, <<0>>)
      end, Ctx0, ModuleFiles),
    Actual = lower_hex(crypto:hash_final(Ctx)),
    Expected = maps:get(<<"build_sha256">>, Manifest),
    require_equal(build_sha256, Expected, Actual).

sha256_hex(Bytes) -> lower_hex(crypto:hash(sha256, Bytes)).
lower_hex(Bin) ->
    unicode:characters_to_binary(string:lowercase(binary_to_list(binary:encode_hex(Bin)))).
normalize_binary(Value) when is_binary(Value) -> Value;
normalize_binary(Value) when is_list(Value) -> unicode:characters_to_binary(Value);
normalize_binary(Value) -> error({invalid_trusted_value, Value}).

verify_trusted_sdk_modules(Names, undefined) ->
    case [Name || Name <- Names, is_trusted_sdk_module(Name)] of
        [] -> ok;
        _ -> error(missing_trusted_sdk_provenance)
    end;
verify_trusted_sdk_modules(Names, Provenance) ->
    SdkModules = [Name || Name <- Names, is_trusted_sdk_module(Name)],
    TrustedSdkSha = maps:get(<<"trusted_sdk_sha256">>, Provenance, null),
    case {SdkModules, TrustedSdkSha} of
        {[], null} -> ok;
        {[], _} -> error({trusted_sdk_provenance_without_modules, TrustedSdkSha});
        {_, null} -> error(missing_trusted_sdk_provenance);
        {_, _} ->
            true = lists:member(<<"bmscl">>, SdkModules),
            ok
    end.

is_trusted_sdk_module(<<"bmscl">>) -> true;
is_trusted_sdk_module(<<"bmscl@", _/binary>>) -> true;
is_trusted_sdk_module(_) -> false.

verify_module_names(Names) ->
    Max = application:get_env(bmscl_supervisor, max_modules_per_artifact, 128),
    case length(Names) =< Max of
        false -> error({too_many_modules, length(Names), Max});
        true -> ok
    end,
    case length(lists:usort(Names)) =:= length(Names) of
        false -> error(duplicate_module_names);
        true -> ok
    end,
    lists:foreach(fun verify_module_name/1, Names), ok.
verify_module_name(Name) when is_binary(Name), byte_size(Name) > 0, byte_size(Name) =< 230 ->
    case re:run(Name, <<"^[a-z][a-zA-Z0-9_@]*$">>, [{capture, none}]) of
        match -> ok;
        nomatch -> error({invalid_tenant_module_name, Name})
    end;
verify_module_name(Name) -> error({invalid_tenant_module_name, Name}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

module_context_contract_rollout_test() ->
    Manifest = #{<<"module_contract_version">> => ?MODULE_CONTRACT_V1,
                 <<"context_abi">> => ?CONTEXT_ABI_V1},
    ?assertEqual(ok, verify_module_context_contract(2, Manifest)),
    ?assertError(
       {unsupported_module_context_contract, <<"bad">>, ?CONTEXT_ABI_V1},
       verify_module_context_contract(
         2, Manifest#{<<"module_contract_version">> => <<"bad">>})),
    ?assertError(
       partial_module_context_contract,
       verify_module_context_contract(2, maps:remove(<<"context_abi">>, Manifest))).

critical_erlang_profile_binding_test() ->
    ?assertEqual(ok,
                 require_language_profile(
                   <<"erlang">>, ?PROFILE_CRITICAL_ERLANG_V1)),
    ?assertError(
       {unsupported_language_profile, <<"erlang">>, ?PROFILE_DURABLE_V1},
       require_language_profile(<<"erlang">>, ?PROFILE_DURABLE_V1)),
    ?assertEqual(
       ok,
       require_capabilities(
         ?PROFILE_CRITICAL_ERLANG_V1,
         lists:sort([<<"ctx.cluster">>, <<"ctx.log">>]))).

trusted_sdk_module_binding_test() ->
    Sha = binary:copy(<<"aa">>, 32),
    Provenance = #{<<"trusted_sdk_sha256">> => Sha},
    ?assertEqual(ok, verify_trusted_sdk_modules(
                       [<<"worker">>, <<"bmscl">>, <<"bmscl@cluster">>],
                       Provenance)),
    ?assertError(missing_trusted_sdk_provenance,
                 verify_trusted_sdk_modules([<<"worker">>, <<"bmscl">>], #{})),
    ?assertError({trusted_sdk_provenance_without_modules, Sha},
                 verify_trusted_sdk_modules([<<"worker">>], Provenance)),
    ?assertError({badmatch, false},
                 verify_trusted_sdk_modules([<<"worker">>, <<"bmscl@cluster">>],
                                            Provenance)).

-endif.
