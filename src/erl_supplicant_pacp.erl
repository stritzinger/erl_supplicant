% Port Access Control Protocol state machine for 802.1x
-module(erl_supplicant_pacp).
-export([start_link/1]).

% Public API
-export([enable/0]).
-export([authenticate/0]).
-export([logoff/0]).

% internal EAP HighLevel API
-export([eap_timeout/0]).
-export([eap_success/0]).
-export([eap_fail/0]).

-behaviour(gen_statem).
-export([init/1, terminate/3, code_change/4, callback_mode/0, handle_event/4]).

-include_lib("kernel/include/logger.hrl").

-record(data, {
    retry_count     :: non_neg_integer(),
    retry_max       :: non_neg_integer()
}).

-define(HELD_PERIOD, 60_000). % 60 seconds is the default

% API

start_link(Opts) ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Opts, []).

enable() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

authenticate() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

logoff() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

eap_timeout() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

eap_success() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

eap_fail() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).
% gen_statem CALLBACKS ---------------------------------------------------------

init(_Opts) ->
    Data = #data{
        retry_count = 0,
        retry_max = 5
    },
    {ok, initialize, Data}.

terminate(_Reason, _State, _Data) -> ok.

code_change(_Vsn, State, Data, _Extra) -> {ok, State, Data}.

callback_mode() -> [handle_event_function, state_enter].

%%% STATE CALLBACKS ------------------------------------------------------------

% INITIALIZE
handle_event(enter, _, initialize, _) ->
    ?LOG_INFO("INITIALIZE"),
    erl_supplicant_eap:eap_stop(),
    keep_state_and_data;
handle_event(cast, enable, initialize, Data) ->
    {next_state, unauthenticated, Data};

% UNAUTHENTICATED
handle_event(enter, _, unauthenticated,
                        #data{retry_count = RetryCount,
                              retry_max = RetryMax} = Data) ->
    case RetryCount >= RetryMax of
        true -> erl_supplicant:failed();
        _ -> ok
    end,
    Data2 = Data#data{retry_count = 0},
    ?LOG_INFO("UNAUTHENTICATED"),
    {keep_state, Data2};
handle_event(cast, authenticate, unauthenticated, Data) ->
    {next_state, authenticating, Data};

% AUTHENTICATING
handle_event(enter, _, authenticating,
                       #data{retry_count = RetryCount} = Data) ->
    Data2 = Data#data{
        retry_count = RetryCount + 1
    },
    ?LOG_INFO("AUTHENTICATING"),
    % Trigger EAP conversation here
    erl_supplicant_eap:eap_start(),
    erl_supplicant_pdu:tx_eapol_start(),
    {keep_state, Data2};
handle_event(cast, eap_timeout, authenticating, #data{retry_count = RC} = D) ->
    case RC < D#data.retry_max of
        true ->
            ?LOG_INFO("EAP Timeout, retrying ..."),
            {repeat_state, D};
        false ->
            {next_state, unauthenticated, D}
    end;
handle_event(cast, logoff, authenticating, Data) ->
    {next_state, logoff, Data};
handle_event(cast, eap_success, authenticating, Data) ->
    {next_state, authenticated, Data};
handle_event(cast, eap_fail, authenticating, Data) ->
    {next_state, held, Data};

% HELD
handle_event(enter, _, held, Data) ->
    erl_supplicant:failed(),
    ?LOG_INFO("HELD"),
    {keep_state, Data, [{state_timeout, ?HELD_PERIOD, end_hold}]};
handle_event(state_timeout, end_hold, held, Data) ->
    {next_state, unauthenticated, Data};

% AUTHENTICATED
handle_event(enter, _, authenticated, Data) ->
    Data2 = Data#data{retry_count = 0},
    ?LOG_INFO("AUTHENTICATED"),
    erl_supplicant:authenticated(),
    {keep_state, Data2};
handle_event(cast, eap_fail, authenticated, Data) ->
    {next_state, authenticating, Data};
handle_event(cast, eap_success, authenticated, _) ->
    ?LOG_INFO("EAP AUTHENTICATION RENEWAL"),
    keep_state_and_data;
handle_event(cast, logoff, authenticated, Data) ->
    {next_state, logoff, Data};

% LOGOFF
handle_event(enter, _, logoff, Data) ->
    ?LOG_INFO("LOGOFF"),
    erl_supplicant_eap:eap_stop(),
    erl_supplicant_pdu:tx_eapol_logoff(),
    {keep_state, Data, [{state_timeout, 0, uct}]};
handle_event(state_timeout, uct, logoff, Data) ->
    {next_state, unauthenticated, Data};

handle_event(E, Content, S, Data) ->
    ?LOG_WARNING("PACP Unhandled Event = ~p, Content = ~p, S = ~p",[E, Content, S]),
    {keep_state, Data}.

% INTERNALS --------------------------------------------------------------------
