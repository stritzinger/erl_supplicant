% The Protocol Data Unit
% Handles trasmission and reception of EAPOL data packets
-module(erl_supplicant_pdu).

-export([start_link/1]).
-export([tx_eapol_start/0]).
-export([tx_eapol_logoff/0]).
-export([eap_msg/1]).

-define(ETH_P_ALL, 16#0300).
-include("../_build/default/lib/procket/include/packet.hrl").
-define(EAPOL, 16#888e).
-include("../_build/default/lib/pkt/include/pkt_802_1x.hrl").

-include_lib("kernel/include/logger.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(NEAREST_NON_TPMR_BRIDGE,
        <<16#01, 16#80, 16#c2, 16#00, 16#00, 16#03>>).

-record(state, {
    port,               % erlang port
    socket,             % socket file descriptor
    interface_index     % index of the interface on the OS
}).


-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

% API

start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

tx_eapol_start() ->
    gen_server:cast(?MODULE, ?FUNCTION_NAME).

tx_eapol_logoff() ->
    gen_server:cast(?MODULE, ?FUNCTION_NAME).

eap_msg(Binary) ->
    gen_server:cast(?MODULE, {?FUNCTION_NAME, Binary}).

% gen_server CALLBACKS ---------------------------------------------------------

init(#{interface := Interface}) ->
    {ok, Fd} = procket:open(0, [
        {protocol, ?ETH_P_ALL},
        {type, dgram},
        {family, packet}]),
    InterfaceIndex = packet:ifindex(Fd, Interface),
    packet:bind(Fd, InterfaceIndex),
    Port = erlang:open_port({fd, Fd, Fd}, [binary, stream]),
    {ok, #state{port = Port, socket = Fd, interface_index = InterfaceIndex}}.

handle_call(Msg, From, State) ->
    ?LOG_ERROR("Unexpected call ~p from ~p",[Msg, From]),
    {reply, ok, State}.

handle_cast(tx_eapol_start, State) ->
    ?LOG_NOTICE("EAPoL Start"),
    do_eapol_send(?EAPOL_START, <<>>, State),
    {noreply, State};
handle_cast(tx_eapol_logoff, State) ->
    ?LOG_NOTICE("EAPoL LogOff"),
    do_eapol_send(?EAPOL_LOGOFF, <<>>, State),
    {noreply, State};
handle_cast({eap_msg, Binary}, State) ->
    do_eapol_send(?EAP_PACKET, Binary, State),
    {noreply, State};
handle_cast(Msg, State) ->
    ?LOG_ERROR("Unexpected cast ~p",[Msg]),
    {noreply, State}.

handle_info({Port, {data, Data}}, #state{port = Port} = State) ->
    try eapol_decode(Data) of
        {?EAP_PACKET, Packet} ->
            erl_supplicant_eap:rx_msg(Packet)
    catch
        error:E ->
            ?LOG_ERROR("Error Decoding ~p",[E])
    end,
    {noreply, State};
handle_info(Msg, State) ->
    ?LOG_NOTICE("Unexpected info ~p",[Msg]),
    {noreply, State}.



% INTERNALS --------------------------------------------------------------------

do_eapol_send(Type, Bin, #state{socket = Socket,
                                interface_index = InterfaceIndex}) ->
    Packet = eapol_encode(Type, Bin),
    send_eth(Socket, ?EAPOL, InterfaceIndex, Packet).

send_eth(Socket, Protocol, Ifindex, Packet) ->
    procket:sendto(Socket, Packet, 0,
    iolist_to_binary([
        <<?PF_PACKET:16/native, % sll_family: PF_PACKET
          Protocol:16,          % sll_protocol: Physical layer protocol
          Ifindex:32/native,  	% sll_ifindex: Interface number
          0:16,		            % sll_hatype: Header type
          0:8,		    		% sll_pkttype: Packet type
          6:8>>,		    	% sll_halen: address length
        ?NEAREST_NON_TPMR_BRIDGE,
        <<0:8, 0:8>>
    ])).

eapol_encode(Type, Binary) ->
    Header = pkt:'802.1x'(#'802.1x'{type = Type, len = byte_size(Binary)}),
    <<Header/binary, Binary/binary>>.

eapol_decode(Packet) ->
    {#'802.1x'{
        ver = Ver,
        type = Type,
        len = Len
    }, Binary} = pkt:'802.1x'(Packet),
    ?assert(Ver == 2),
    <<Payload:Len/binary,_/binary>> = Binary,
    {Type, Payload}.
