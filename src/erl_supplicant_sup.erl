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
    % {ok, Interface} = application:get_env(erl_supplicant, interface),
    {ok, Identity} = application:get_env(erl_supplicant, eap_identity),
    {ok, Timeout} = application:get_env(erl_supplicant, eap_timeout),
    {ok, RetryMax} = application:get_env(erl_supplicant, pacp_retry_max),
    {ok, HeldPeriod} = application:get_env(erl_supplicant, pacp_held_period),
    {ok, Auto} = application:get_env(erl_supplicant, auto),
    ChildSpecs = [
        % worker(erl_supplicant_pdu, [#{interface => Interface}]),
        worker(erl_supplicant_eap_tls, []),
        worker(erl_supplicant_eap, [#{identity => Identity, timeout => Timeout}]),
        worker(erl_supplicant_pacp, [#{retry_max => RetryMax, held_period => HeldPeriod}]),
        worker(erl_supplicant, [#{auto => Auto}])
    ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions

worker(Module, Args) ->
    #{id => Module, start => {Module, start_link, Args}, type => worker}.
