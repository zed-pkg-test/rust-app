-module(bmscl_durable_store).

%% Storage contract for BeamScale Durable Actors.
%%
%% Implementations are responsible for durable object state and stale-owner
%% rejection. The in-memory runtime registry is not a fencing authority.
%%
%% Durable state crosses process/node/release boundaries, so this contract uses
%% an opaque binary payload rather than arbitrary Erlang terms. Trusted runtime
%% codecs may encode structured values before storage, but PIDs, refs, funs,
%% ports, and other VM-local terms must never become part of the durable format.
%%
%% Fencing is scoped to a virtual shard, not to one object. That is essential:
%% after failover, a newly assigned shard owner must fence the stale owner from
%% every object in the shard even before the new owner has loaded each object.

-export_type([
    identity/0,
    owner_scope/0,
    owner_epoch/0,
    version/0,
    loaded/0,
    claim_result/0,
    commit_result/0
]).

%% Stable logical identity. Physical placement is deliberately excluded so
%% shard/bucket/node changes never change the durable object's key.
-type identity() :: #{
    tenant_id := binary(),
    application_id := binary(),
    namespace := binary(),
    object_key := binary()
}.

%% Fencing scope for one virtual shard. Actor buckets may be regrouped later,
%% but a shard remains the minimum independently movable ownership unit in V1.
-type owner_scope() :: #{
    tenant_id := binary(),
    application_id := binary(),
    namespace := binary(),
    virtual_shard := non_neg_integer()
}.

-type owner_epoch() :: pos_integer().
-type version() :: non_neg_integer().

-type loaded() :: #{
    version := version(),
    state := binary()
}.

-type claim_result() ::
    {ok, owner_epoch()}
    | {error, term()}.

-type commit_result() ::
    {ok, version()}
    | {error, {stale_version, version()}}
    | {error, {stale_owner_epoch, owner_epoch()}}
    | {error, term()}.

%% Load the latest durable object state. Loading state does not grant ownership.
%% OwnerScope is supplied so clustered stores can deliberately co-locate the
%% object row with its shard-owner fencing record for one atomic commit.
-callback load(identity(), owner_scope()) ->
    {ok, not_found}
    | {ok, loaded()}
    | {error, term()}.

%% Atomically allocate and persist the next ownership epoch for a virtual shard.
%%
%% The caller MUST NOT choose the epoch. The authoritative backend allocates a
%% strictly increasing value so restarts, partitions, or buggy callers cannot
%% roll ownership backward or jump to an unverified caller-selected token.
-callback claim_owner(owner_scope()) -> claim_result().

%% Atomically commit object state only when:
%%   1. ExpectedVersion still matches the object's durable version; and
%%   2. OwnerEpoch is the current authoritative epoch for OwnerScope.
%%
%% The ownership check MUST be against the shard ownership record, not against
%% an epoch copied only into the individual object row. Otherwise a stale owner
%% could still write an object that the new owner has not loaded yet.
-callback commit(
    identity(),
    version(),
    owner_scope(),
    owner_epoch(),
    binary()
) -> commit_result().
