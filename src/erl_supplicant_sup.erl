%%%-------------------------------------------------------------------
%% @doc erl_supplicant top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(erl_supplicant_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_all},
    {ok, Interface} = application:get_env(erl_supplicant, interface),
    {ok, Identity} = application:get_env(erl_supplicant, identity),
    Auto = application:get_env(erl_supplicant, auto, true),
    ChildSpecs = [
        worker(erl_supplicant_pdu, [#{interface => Interface}]),
        worker(erl_supplicant_eap_tls, []),
        worker(erl_supplicant_eap, [#{identity => Identity}]),
        worker(erl_supplicant_pacp, [#{}]),
        worker(erl_supplicant, [#{auto => Auto}])
    ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions

worker(Module, Args) ->
    #{id => Module, start => {Module, start_link, Args}, type => worker}.
