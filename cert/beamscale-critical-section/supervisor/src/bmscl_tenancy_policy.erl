-module(bmscl_tenancy_policy).

-export([class/1, validate/2]).

%% Durable actors/critical sections are single-tenant per BEAM OS process.
%% Lambda is the flagship FaaS product: free may multiplex tenants in one BEAM
%% process, while pro is tenant-dedicated.
class(durable_actor_v1) -> tenant_dedicated;
class(critical_section_v1) -> tenant_dedicated;
class(lambda_free_v1) -> mixed_tenants;
class(lambda_pro_v1) -> tenant_dedicated;
class(_) -> undefined.

validate(Profile, Requested) ->
    case class(Profile) of
        undefined -> {error, {unknown_tenancy_profile, Profile}};
        Requested -> ok;
        Required -> {error, {tenancy_class_mismatch, Required, Requested}}
    end.
