-module(example_module).
-behaviour(bmscl_module).

-export([handle/2, module_kind/0, module_name/0]).

-spec module_kind() -> lambda.
module_kind() ->
    lambda.

-spec module_name() -> binary().
module_name() ->
    <<"example">>.

-spec handle(term(), term()) -> {ok, term()} | {error, term()}.
handle(_Context, Input) ->
    {ok, Input}.
