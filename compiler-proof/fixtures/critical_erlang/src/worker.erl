-module(worker).
-export([handle/2]).

handle(_Request, _Context) ->
    {response, 200,
     [{<<"content-type">>, <<"application/json">>}],
     <<"{\"ok\":true}">>}.
