% The Protocol Data Unit
% Handles trasmission and reception of EAPoL data packets
-module(erl_supplicant_pdu).

-export([initialize/0]).
-export([tx_eapol_start/1]).
-export([tx_eapol_logoff/1]).
-export([tx_eap_msg/2]).
-export([handle_data/2]).
-export([shutdown/1]).

% -define(ETH_P_ALL, 16#0300).
-include_lib("procket/include/packet.hrl").
-define(ETH_P_EAPOL, 16#888e).
-include_lib("pkt/include/pkt_802_1x.hrl").

-include_lib("kernel/include/logger.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(dot1Q, 16#01, 16#80, 16#c2, 16#00, 16#00).
% From top to bottom:
% the least filtered to the most filtered MAC destination address for eapol PDUs
-define(EDE_CC_PEP_ADDR, <<?dot1Q, 16#1f>>).
-define(NEAREST_CUSTOMER_BRIDGE, <<?dot1Q, 16#00>>).
-define(EDE_SS_PEP_ADDR, <<?dot1Q, 16#0b>>).
-define(NEAREST_NON_TPMR_BRIDGE, <<?dot1Q, 16#03>>).
-define(NEAREST_BRIDGE, <<?dot1Q, 16#0e>>).

-record(state, {
    mac_addr,      % name in string form
    port,               % erlang port
    socket,             % socket file descriptor
    interface_index     % index of the interface on the OS
}).


% API

initialize() ->
    {ok, Interface} = application:get_env(erl_supplicant, interface),
    {ok, Fd} = procket:open(0, [
        {protocol, 16#8e88}, %?ETH_P_EAPOL with switched bytes
        {type, raw},
        {family, packet}]),
    InterfaceIndex = packet:ifindex(Fd, Interface),
    packet:bind(Fd, InterfaceIndex),
    Port = erlang:open_port({fd, Fd, Fd}, [binary, stream]),
    {ok, #state{
        mac_addr = get_mac_of_interface(Interface),
        port = Port,
        socket = Fd,
        interface_index = InterfaceIndex}}.


shutdown(#state{port = Port, socket = Fd}) ->
    erlang:port_close(Port),
    procket:close(Fd),
    #state{}.

tx_eapol_start(State) ->
    ?LOG_INFO("EAPoL Start"),
    do_eapol_send(?EAPOL_START, <<>>, State),
    State.

tx_eapol_logoff(State) ->
    ?LOG_INFO("EAPoL LogOff"),
    do_eapol_send(?EAPOL_LOGOFF, <<>>, State),
    State.

tx_eap_msg(Binary, State) ->
    do_eapol_send(?EAP_PACKET, Binary, State),
    State.

handle_data({Port, {data,<<_:6/binary, _:6/binary,
                           ?ETH_P_EAPOL:16,
                           DGRAM/binary>>}},
            #state{port = Port} = State) ->
    try eapol_decode(DGRAM) of
        {?EAP_PACKET, Packet} ->
            erl_supplicant_eap:rx_msg(Packet);
        {Type, _Packet} ->
            ?LOG_DEBUG("Unexpected packet type: ~p",[Type])
    catch
        error:E ->
            ?LOG_DEBUG("Error Decoding ~p",[E])
    end,
    State;
handle_data({Port, {data, P}}, State) ->
    % Ignoring other protocols,
    % but anything other then EAPOL should not come from the socket
    ?LOG_ERROR("Unexpected ETH packet: ~p",[P]),
    State.

% INTERNALS --------------------------------------------------------------------

do_eapol_send(Type, Bin, #state{mac_addr = MAC, socket = Socket,
                                interface_index = InterfaceIndex}) ->
    Packet = eapol_encode(Type, Bin),
    DST = ?NEAREST_NON_TPMR_BRIDGE,
    Eth2 = <<DST/binary, MAC/binary, ?ETH_P_EAPOL:16, Packet/binary>>,
    packet:send(Socket, InterfaceIndex, Eth2).

% In case of dgram mode...
% send_eth(Socket, Protocol, Ifindex, Packet) ->
%     procket:sendto(Socket, Packet, 0,
%     iolist_to_binary([
%         <<?PF_PACKET:16/native, % sll_family: PF_PACKET
%           Protocol:16,          % sll_protocol: Physical layer protocol
%           Ifindex:32/native,  	% sll_ifindex: Interface number
%           0:16,		            % sll_hatype: Header type
%           0:8,		    		% sll_pkttype: Packet type
%           6:8>>,		    	% sll_halen: address length
%         ?NEAREST_NON_TPMR_BRIDGE,
%         <<0:8, 0:8>>
%     ])).

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


get_mac_of_interface(Interface) ->
    {ok, Interfaces} = inet:getifaddrs(),
    [Opts|_] = [Opts || {Name, Opts} <- Interfaces, Name == Interface],
    {hwaddr, MAC} = proplists:lookup(hwaddr, Opts),
    list_to_binary(MAC).