-module(bmscl_module).

-callback handle(Context :: term(), Input :: term()) ->
    {ok, Output :: term()} | {error, Reason :: term()}.

-callback module_kind() -> lambda | http | rpc | actor | worker.
-callback module_name() -> binary().

-optional_callbacks([module_name/0]).
