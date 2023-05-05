-module(erl_supplicant).

-export([start_link/1]).
-export([authenticated/0]).

% Public API
-export([authenticate/0]).

% Internal API
-export([authenticated/0]).
-export([failed/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

% API

start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

-spec authenticate() -> success | failure.
authenticate() -> gen_server:call(?MODULE, ?FUNCTION_NAME, 60_000).

authenticated() -> gen_server:cast(?MODULE, ?FUNCTION_NAME).

failed() -> gen_server:cast(?MODULE, ?FUNCTION_NAME).


% gen_server CALLBACKS ---------------------------------------------------------

init(#{auto := Auto}) ->
    erl_supplicant_pacp:enable(),
    case Auto of
        true ->
            erl_supplicant_pacp:authenticate(),
            {ok, {authenticating, self}};
        false ->
            {ok, []}
    end.

handle_call(authenticate, _, {authenticating, _Caller} = S) ->
    {reply, already_authenticating, S};
handle_call(authenticate, From, _State) ->
    erl_supplicant_pacp:authenticate(),
    {noreply, {authenticating, From}};
handle_call(Msg, From, State) ->
    ?LOG_ERROR("Unexpected call ~p from ~p",[Msg, From]),
    {reply, ok, State}.

handle_cast(authenticated, State) ->
    ?LOG_NOTICE("ERL_SUPP AUTHENTICATED"),
    case State of
        {authenticating, self} -> ok;
        {authenticating, Caller} ->
            gen_server:reply(Caller, success)
    end,
    {noreply, State};
handle_cast(failed, {authenticating, Caller}) ->
    ?LOG_NOTICE("ERL_SUPP FAILED AUTHENTICATION"),
    case Caller of
        self -> ok;
        _ -> gen_server:reply(Caller, failure)
    end,
    {noreply, []};
handle_cast(Msg, State) ->
    ?LOG_ERROR("Unexpected cast ~p",[Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    ?LOG_NOTICE("Unexpected info ~p",[Msg]),
    {noreply, State}.


% INTERNALS --------------------------------------------------------------------
