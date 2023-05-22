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
-export([eap_msg/1]).

-behaviour(gen_statem).
-export([init/1, terminate/3, code_change/4, callback_mode/0, handle_event/4]).

-include_lib("kernel/include/logger.hrl").

-record(data, {
    retry_count     :: non_neg_integer(),
    retry_max       :: non_neg_integer(),
    held_period     :: non_neg_integer(),
    pdu_state       :: term()
}).

% API

start_link(Opts) ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Opts, []).

enable() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

authenticate() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

logoff() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

eap_msg(Binary) -> gen_statem:cast(?MODULE, {?FUNCTION_NAME, Binary}).

eap_timeout() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

eap_success() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).

eap_fail() -> gen_statem:cast(?MODULE, ?FUNCTION_NAME).
% gen_statem CALLBACKS ---------------------------------------------------------

init(#{retry_max := Max}) ->
    Data = #data{
        held_period = 1000,
        retry_count = 0,
        retry_max = Max
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
        true -> erl_supplicant:failed(max_retry_reached);
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
    ?LOG_INFO("AUTHENTICATING"),
    % Trigger EAP conversation here
    {ok, NewPduState} = erl_supplicant_pdu:initialize(),
    erl_supplicant_eap:eap_start(),
    erl_supplicant_pdu:tx_eapol_start(NewPduState),
    Data2 = Data#data{
        retry_count = RetryCount + 1,
        pdu_state = NewPduState
    },
    {keep_state, Data2};
handle_event(cast, eap_timeout, authenticating, #data{retry_count = RC, pdu_state = PduState} = D) ->
    case RC < D#data.retry_max of
        true ->
            PDU = erl_supplicant_pdu:shutdown(PduState),
            ?LOG_INFO("EAP Timeout, retrying ..."),
            {repeat_state, D#data{pdu_state = PDU}};
        false ->
            {next_state, unauthenticated, D}
    end;
handle_event(cast, authenticate, authenticating, _Data) ->
    keep_state_and_data;
handle_event(cast, {eap_msg, Bin}, authenticating, #data{pdu_state = PduState}) ->
    erl_supplicant_pdu:tx_eap_msg(Bin, PduState),
    keep_state_and_data;
handle_event(cast, logoff, authenticating, Data) ->
    {next_state, logoff, Data};
handle_event(cast, eap_success, authenticating, Data) ->
    {next_state, authenticated, Data};
handle_event(cast, eap_fail, authenticating, Data) ->
    {next_state, held, Data};

% HELD
handle_event(enter, _, held,
            #data{held_period = HeldPeriod, pdu_state = PduState} = Data) ->
    NewPduState = erl_supplicant_pdu:shutdown(PduState),
    erl_supplicant:failed(eap_fail),
    ?LOG_INFO("HELD"),
    {keep_state, Data#data{pdu_state = NewPduState},
                [{state_timeout, HeldPeriod, end_hold}]};
handle_event(state_timeout, end_hold, held, Data) ->
    {next_state, unauthenticated, Data};
handle_event(cast, authenticate, held, _Data) ->
    {keep_state_and_data, [postpone]};

% AUTHENTICATED
handle_event(enter, _, authenticated, #data{} = Data) ->
    ?LOG_INFO("AUTHENTICATED"),
    erl_supplicant:authenticated(),
    {keep_state, Data#data{retry_count = 0}};
handle_event(cast, {eap_msg, Bin}, authenticated, #data{pdu_state = PduState}) ->
    erl_supplicant_pdu:tx_eap_msg(Bin, PduState),
    keep_state_and_data;
handle_event(cast, eap_fail, authenticated, Data) ->
    {next_state, authenticating, Data};
handle_event(cast, eap_success, authenticated, _) ->
    ?LOG_INFO("EAP AUTHENTICATION RENEWAL"),
    keep_state_and_data;
handle_event(cast, logoff, authenticated, Data) ->
    {next_state, logoff, Data};

% LOGOFF
handle_event(enter, _, logoff, #data{pdu_state = PduState} = Data) ->
    ?LOG_INFO("LOGOFF"),
    erl_supplicant_eap:eap_stop(),
    erl_supplicant_pdu:tx_eapol_logoff(),
    NewPduState = erl_supplicant_pdu:shutdown(PduState),
    {keep_state, Data#data{pdu_state = NewPduState}, [{state_timeout, 0, uct}]};
handle_event(state_timeout, uct, logoff, Data) ->
    {next_state, unauthenticated, Data};

% Incoming network traffic
handle_event(info, {_Port, {data, _}} = PortMsg, _, #data{pdu_state = PduState} = Data) ->
    NewPduState = erl_supplicant_pdu:handle_data(PortMsg, PduState),
    {keep_state, Data#data{pdu_state = NewPduState}};

handle_event(E, Content, S, Data) ->
    ?LOG_WARNING("PACP Unhandled Event = ~p, Content = ~p, S = ~p",[E, Content, S]),
    {keep_state, Data}.

% INTERNALS --------------------------------------------------------------------
