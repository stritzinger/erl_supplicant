%%%-------------------------------------------------------------------
%% @doc erl_supplicant public API
%% @end
%%%-------------------------------------------------------------------

-module(erl_supplicant_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    erl_supplicant_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
