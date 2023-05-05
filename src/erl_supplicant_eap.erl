% Extendable Access Protocol
% common layer to handle all EAP methods
-module(erl_supplicant_eap).

-export([start_link/1]).
-export([eap_start/0]).
-export([eap_stop/0]).
-export([rx_msg/1]).
% -export([tx_msg/2]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

-record(state, {
    identity        :: string(),
    eap_state       :: undefined | start | stop | timeout | fail | success,
    timeout_ref
    % This id is just for active supplicant requests,
    % maybe delete, never used?
    % request_id = 0
}).

-define(EAP_TIMEOUT, 10_000).

% EAP Codes
-define(Request, 1).
-define(Response, 2).
-define(Success, 3).
-define(Failure, 4).

% Supported EAP types - RFC 3748
-define(Identify, 1).
% TODO: suport minimal subset to comply to the RFC
% -define(Notification, 2).
% -define(NAK, 3).
% -define(MD5_Challenge, 4).
-define(EAP_TLS, 13).


% API

start_link(Opts) -> gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

eap_start() -> gen_server:call(?MODULE, ?FUNCTION_NAME).

eap_stop() -> gen_server:call(?MODULE, ?FUNCTION_NAME).

rx_msg(Binary) -> gen_server:cast(?MODULE, {?FUNCTION_NAME, Binary}).

% tx_msg(eap_tls, Binary) ->
%     gen_server:cast(?MODULE, {?FUNCTION_NAME, ?EAP_TLS, Binary}).

% gen_server CALLBACKS ---------------------------------------------------------

init(#{identity := Identity}) ->
    {ok, #state{identity = Identity}}.

handle_call(eap_stop, _, S) ->
    erl_supplicant_eap_tls:stop(),
    {reply, ok, clear_timer(S#state{eap_state = stop})};
handle_call(eap_start, _, S) ->
    {ok, Tref} = timer:send_after(?EAP_TIMEOUT, timeout),
    {reply, ok, S#state{eap_state = start, timeout_ref = Tref}};
handle_call(Msg, From, S) ->
    ?LOG_ERROR("Unexpected call ~p from ~p",[Msg, From]),
    {reply, ok, S}.


handle_cast({rx_msg, _}, #state{eap_state = EAP} = S)
when (EAP == stop) or (EAP == eap_fail) ->
    ?LOG_INFO("Ignoring eap msg in eap_state: ~p", [EAP]),
    {noreply, S};
handle_cast({rx_msg, Binary}, #state{eap_state = _} = S) ->
    {noreply, handle_eap_msg(Binary, S)};
% handle_cast({tx_msg, Type, Binary}, S) ->
%     {noreply, send_eap_request(Type, Binary, S)};
handle_cast(Msg, S) ->
    ?LOG_ERROR("Unexpected cast ~p",[Msg]),
    {noreply, S}.

handle_info(timeout, #state{eap_state = start} = S) ->
    erl_supplicant_pacp:eap_timeout(),
    {noreply, S#state{eap_state = timeout}};
handle_info(Msg, S) ->
    ?LOG_ERROR("Unexpected info ~p",[Msg]),
    {noreply, S}.

% INTERNALS --------------------------------------------------------------------

% send_eap_request(Type, TypeData, #state{request_id = ID} = S) ->
%     NewID = ID +1,
%     ?LOG_DEBUG("EAP requesting ~p", [NewID]),
%     Binary = eap_encode(?Request, list_to_binary([Type | TypeData]), NewID),
%     erl_supplicant_pdu:eap_msg(Binary),
%     S#state{request_id = NewID}.

handle_eap_msg(Binary, S) ->
    case eap_decode(Binary) of
        {Code, Data, Id} -> process_msg(Code, Data, Id, S);
        bad_eap ->
            ?LOG_ERROR("Bad EAP msg: ~p",[Binary]),
            S
    end.

process_msg(?Request, <<Type:8/unsigned, TypeData/binary>>, Id, S) ->
    ?LOG_DEBUG("EAP request ~p type: ~p", [Id, Type]),
    handle_request(Type, TypeData, Id, S);
process_msg(?Response, <<Type:8/unsigned, TypeData/binary>>, Id, S) ->
    ?LOG_DEBUG("EAP responce ~p type: ~p", [Id, Type]),
    handle_responce(Type, TypeData, Id, S);
process_msg(?Success, <<>>, Id, S) ->
    ?LOG_DEBUG("EAP SUCCESS:  ~p", [Id]),
    erl_supplicant_pacp:eap_success(),
    erl_supplicant_eap_tls:stop(),
    clear_timer(S#state{eap_state = success});
process_msg(?Failure, <<>>, Id, S) ->
    ?LOG_DEBUG("EAP FAILURE:  ~p", [Id]),
    erl_supplicant_pacp:eap_fail(),
    clear_timer(S#state{eap_state = fail}).

handle_request(?Identify, _, Id, #state{identity = Identity} = S) ->
    reply(?Identify, [Identity], Id),
    S;
handle_request(?EAP_TLS, TypeData, Id, S) ->
    Reply = erl_supplicant_eap_tls:handle_request(TypeData),
    reply(?EAP_TLS, Reply, Id),
    S;
handle_request(Type, _, _Id, S) ->
    ?LOG_WARNING("EAP type not recognised: ~p", [Type]),
    S.

handle_responce(_, _, _, _) ->
    error(not_implemented).

reply(Type, Args, Id) ->
    ?LOG_DEBUG("EAP replying ~p", [Id]),
    Binary = eap_encode(?Response, list_to_binary([Type | Args]), Id),
    erl_supplicant_pdu:eap_msg(Binary).

eap_encode(Code, Data, Identifier) ->
    <<Code:8/unsigned,
      Identifier:8/unsigned,
      (byte_size(Data) + 4):16/unsigned,
      Data/binary>>.

eap_decode(<<Code:8/unsigned,
             Identifier:8/unsigned,
             Len:16/unsigned,
             Data/binary>>) ->
    <<EAP_Data:(Len-4)/binary,_Pad/binary>> = Data,
    {Code, EAP_Data, Identifier};
eap_decode(_) ->
    bad_eap.

clear_timer(#state{timeout_ref = Tref} = S) ->
    timer:cancel(Tref),
    S#state{timeout_ref = undefined}.
