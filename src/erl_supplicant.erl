-module(erl_supplicant).

-export([start_link/0]).

-export([authenticated/0]).
-export([failed/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

% API

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

authenticated() -> gen_server:cast(?MODULE, ?FUNCTION_NAME).

failed() -> gen_server:cast(?MODULE, ?FUNCTION_NAME).


% gen_server CALLBACKS ---------------------------------------------------------

init([]) ->
    erl_supplicant_pacp:enable(),
    erl_supplicant_pacp:authenticate(),
    {ok, init}.

handle_call(Msg, From, State) ->
    ?LOG_ERROR("Unexpected call ~p from ~p",[Msg, From]),
    {reply, ok, State}.

handle_cast(authenticated, State) ->
    % Do something here?
    {noreply, State};
handle_cast(failed, State) ->
    % Do something here?
    {noreply, State};
handle_cast(Msg, State) ->
    ?LOG_ERROR("Unexpected cast ~p",[Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    ?LOG_NOTICE("Unexpected info ~p",[Msg]),
    {noreply, State}.


% INTERNALS --------------------------------------------------------------------
