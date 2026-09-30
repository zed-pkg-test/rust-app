-module(bmscl_test_durable_store).

-export([reset/0, load/2, claim_owner/1, commit/5]).

-define(TABLE, bmscl_test_durable_store_table).

reset() ->
    case ets:whereis(?TABLE) of
        undefined -> ok;
        _ -> ets:delete(?TABLE), ok
    end.

claim_owner(Scope) ->
    ensure_table(),
    Epoch = ets:update_counter(
              ?TABLE, {owner, Scope}, {2, 1}, {{owner, Scope}, 0}),
    {ok, Epoch}.

load(Identity, _Scope) ->
    ensure_table(),
    case ets:lookup(?TABLE, {object, Identity}) of
        [] -> {ok, not_found};
        [{{object, Identity}, Version, Payload}] ->
            {ok, #{version => Version, state => Payload}}
    end.

commit(Identity, ExpectedVersion, Scope, OwnerEpoch, Payload) ->
    ensure_table(),
    case ets:lookup(?TABLE, {owner, Scope}) of
        [] -> {error, owner_missing};
        [{{owner, Scope}, CurrentOwner}] when CurrentOwner =/= OwnerEpoch ->
            {error, {stale_owner_epoch, CurrentOwner}};
        [{{owner, Scope}, OwnerEpoch}] ->
            CurrentVersion = case ets:lookup(?TABLE, {object, Identity}) of
                [] -> 0;
                [{{object, Identity}, Version, _}] -> Version
            end,
            case CurrentVersion =:= ExpectedVersion of
                false -> {error, {stale_version, CurrentVersion}};
                true ->
                    Next = CurrentVersion + 1,
                    true = ets:insert(
                             ?TABLE,
                             {{object, Identity}, Next, Payload}),
                    {ok, Next}
            end
    end.

ensure_table() ->
    case ets:whereis(?TABLE) of
        undefined ->
            try ets:new(?TABLE, [named_table, public, set]) of
                _ -> ok
            catch
                error:badarg -> ok
            end;
        _ -> ok
    end.
