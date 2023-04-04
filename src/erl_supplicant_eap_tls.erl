% This module tunnels a TLS conversation in EAP requests/replies
% It manages fragmentation, splitting replyes and re-assembling requests.
% It also mocks the inet and gen_tcp API to keep the OTP ssl app happy.
-module(erl_supplicant_eap_tls).

% API
-export([start_link/0]).
-export([handle_request/1]).
-export([handle_responce/1]).
-export([stop/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).


-include_lib("kernel/include/logger.hrl").
-include_lib("stdlib/include/assert.hrl").

% mocking gen_tcp
-export([
         connect/4,
         send/2,
         close/1,
         controlling_process/2,
         setopts/2,
         getopts/2,
         peername/1,
         sockname/1,
         port/1
]).

-record(state, {
    tls_client      :: undefined | pid(),
    tls_connection  :: undefined | ssl:sslsocket(),
    pending_call = none,
    packet_length,
    fragments = []
}).
% Find a clever way to determinate an appropriate MTU.
% Assuming an MTU of 1024 bytes:
% -14 for the Ethernet II header
% -4 for the 802.1x header
% -5 for the EAP header
% -1 EAP-TLS flags
% = 1000 bytes
% (but 996 if -4 for optional EAP-TLS Length)
-define(TLS_MTU, 1000).

%EAP-TLS flags
-define(LENGTH, (1 bsl 7)).
-define(MORE_FRAGMENTS, (1 bsl 6)).
-define(EAP_TLS_START, (1 bsl 5)).

-define(has_flag(Flags, F), ((Flags band F) /= 0) ).

-define(start(F), ?has_flag(F, ?EAP_TLS_START)).
-define(is_fragment(F), ?has_flag(F, ?LENGTH) and
                        ?has_flag(F, ?MORE_FRAGMENTS)).
-define(end_fragment(F), ?has_flag(F, ?LENGTH) and
                         (not ?has_flag(F, ?MORE_FRAGMENTS))).
-define(is_ack(F), F == 0).

% API -------------------------------------------------------------------------

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

handle_request(Request) ->
    gen_server:call(?MODULE, {?FUNCTION_NAME, Request}).

handle_responce(_) ->
    error(not_implemented).

stop() ->
    gen_server:cast(?MODULE, ?FUNCTION_NAME).

% Mocking gen_tcp -------------------------------------------------------------

connect(_, _, _, _) -> {ok, fake_socket}.

send(fake_socket, Message) ->
    gen_server:cast(?MODULE, {?FUNCTION_NAME, Message}).

close(fake_socket) -> ok.

controlling_process(fake_socket, Pid) ->
    gen_server:cast(?MODULE, {?FUNCTION_NAME, Pid}).

setopts(fake_socket, _Options) ->  ok.

getopts(fake_socket, _Options) ->
    {ok, [{packet_size,0},
          {header,0},
          {active,false},
          {packet,0},
          {mode,binary}]}.

peername(fake_socket) -> {ok, {{127,0,0,1}, 443}}.

sockname(fake_socket) -> {ok, {{127,0,0,1}, 0}}.

port(fake_socket) -> {ok, 0}.

%% gen_server callbacks -------------------------------------------------------

init([]) ->
    {ok, #state{}}.

handle_call({handle_request, Binary}, From, _S) ->
    do_handle_request(Binary, From, _S);
handle_call(Msg, From, State) ->
    ?LOG_ERROR("Unexpected call ~p from ~p",[Msg, From]),
    {reply, error, State}.

handle_cast({tls_connection_ref, SSL_Socket}, S) ->
    {noreply, S#state{tls_connection = SSL_Socket}};
handle_cast({controlling_process, Pid}, S) ->
    {noreply, S#state{tls_client = Pid}};
handle_cast(stop, #state{tls_connection = SSL_Socket}) ->
    case SSL_Socket of
        undefined ->
            {noreply, #state{}};
        _ ->
            ssl:close(SSL_Socket),
            {noreply, #state{}}
    end;
handle_cast({send, _}, #state{pending_call = none,
                              tls_connection = undefined,
                              tls_client = undefined} = S) ->
    % After calling ssl:close() we ignore send commands
    % Why?: SSL sends an encrypted alert to close the connection.
    % But for 802.1X Authentication this is not needed
    {noreply, S};
handle_cast({send, SSL_Message}, S) ->
    S1 = fragment_message(SSL_Message, S),
    {noreply, send_chunk(S1)};
handle_cast(Msg, S) ->
    ?LOG_ERROR("Unexpected cast ~p",[Msg]),
    {noreply, S}.

handle_info(Msg, S) ->
    ?LOG_ERROR("Unexpected info ~p",[Msg]),
    {noreply, S}.

% INTERNAL --------------------------------------------------------------------

do_handle_request(<<Flags:8/unsigned, _/binary>>, From, _S) when ?start(Flags) ->
    ?LOG_DEBUG("EAP-TLS Start"),
    trigger_tls_conversation(),
    {noreply, #state{pending_call = From, fragments = []}};
do_handle_request(<<Flags:8/unsigned, Length:32/unsigned, Data/binary>>,
                  _, #state{fragments = F} = S) when ?is_fragment(Flags) ->
    ?LOG_DEBUG("EAP-TLS Fragment"),
    EmptyFlags = <<0:8/unsigned>>,
    {reply, EmptyFlags, S#state{packet_length = Length, fragments = [Data | F]}};
do_handle_request(<<Flags:8/unsigned, Length:32/unsigned, Data/binary>>,
                  From, #state{fragments = F, tls_client = Pid} = S)
                  when ?end_fragment(Flags) ->
    ?LOG_DEBUG("EAP-TLS Final"),
    Binary = list_to_binary(lists:reverse([Data|F])),
    ?assertMatch(Length, byte_size(Binary)),
    % send to tls process
    Pid ! {eap, fake_socket, Binary},
    {noreply, S#state{packet_length = undefined,fragments = [], pending_call = From}};
do_handle_request(<<Flags:8/unsigned, _Data/binary>>, From, S) when ?is_ack(Flags) ->
    % empty requests are sent to receive the next fragment as reply
    % they act as ACK messages
    ?LOG_DEBUG("EAP-TLS ACK"),
    {noreply, send_chunk(S#state{pending_call = From})}.

fragment_message(Message, #state{fragments = F} = S) ->
    Binary = list_to_binary(Message),
    TotalLength = byte_size(Binary),
    ?assert(length(F) == 0),
    case TotalLength > ?TLS_MTU of
        true ->
            S#state{packet_length = TotalLength,
                    fragments = split(Binary, ?TLS_MTU -4)};
        false ->
            S#state{packet_length = undefined, fragments = [Binary]}
    end.

split(Binary, Max) ->
    F = fun
        Split(<<Chunk:Max/binary, Rest/binary>>, Res) ->
            Split(Rest, [Chunk|Res]);
        Split(<<LastChunk/binary>> , Res) ->
            lists:reverse([LastChunk|Res])
    end,
    F(Binary, []).

% send_chunk(#state{pending_call = none,
%                   packet_length = L,
%                   fragments = [F|TL]} = S) ->
%     Header = gen_chunk_header(L, TL),
%     erl_supplicant_eap:tx_msg(eap_tls, [Header, F]),
    % S#state{fragments = TL};
send_chunk(#state{pending_call = From,
                  packet_length = L,
                  fragments = [F|TL]} = S) ->
    Header = gen_chunk_header(L, TL),
    gen_server:reply(From, [Header, F]),
    S#state{fragments = TL, pending_call = none}.

gen_chunk_header(undefined, []) -> <<0:8>>;
gen_chunk_header(L, []) -> <<(?LENGTH):8, L:32/unsigned>>;
gen_chunk_header(PktLen, _RemainingFragments) ->
        <<(?LENGTH bor ?MORE_FRAGMENTS):8, PktLen:32/unsigned>>.


trigger_tls_conversation() ->
    UserOpts = application:get_env(erl_supplicant, eap_tls, []),
    CustomTransport = {cb_info, {
        ?MODULE,
        eap,        % Data Tag
        eap_stop,
        eap_error,
        eap_passive}},
    TLS_Opts = [CustomTransport | UserOpts],
    {ok, CN} = application:get_env(erl_supplicant, server_common_name),

    spawn(fun() ->
        Ret = ssl:connect(CN, fake_port, TLS_Opts),
        ?LOG_DEBUG("EAP-TLS SSL app returned! ~p",[Ret]),
        case Ret of
            {ok, SSL} ->
                EAP_TLS_proc = whereis(?MODULE),
                ssl:controlling_process(SSL, EAP_TLS_proc),
                gen_server:cast(?MODULE, {tls_connection_ref, SSL}),
                gen_server:cast(?MODULE, {send, []})
        end
    end).
