%%%-------------------------------------------------------------------
%% @doc floaty_erl public API
%% @end
%%%-------------------------------------------------------------------

-module(floaty_erl_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    % Create data directory if it doesn't exist
    filelib:ensure_dir("data/"),
    
    % Get configuration
    {ok, Port} = application:get_env(floaty_erl, port),
    {ok, NoAuth} = application:get_env(floaty_erl, no_auth),
    
    % Initialize session storage ETS table
    ets:new(sessions, [named_table, public, set]),
    
    % Log authentication status
    case NoAuth of
        true -> 
            io:format("Warning: Running in NO AUTH mode. Application is publicly accessible!~n");
        false ->
            {ok, Username} = application:get_env(floaty_erl, username),
            {ok, Password} = application:get_env(floaty_erl, password),
            case {Username, Password} of
                {<<"admin">>, _} ->
                    io:format("Warning: Using default username 'admin'. Set FLOATY_USERNAME environment variable for production.~n");
                _ -> ok
            end,
            case {Username, Password} of
                {_, <<"floaty">>} ->
                    io:format("Warning: Using default password 'floaty'. Set FLOATY_PASSWORD environment variable for production.~n");
                _ -> ok
            end
    end,
    
    % Setup routes
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/static/[...]", cowboy_static, {dir, "static"}},
            {"/login", floaty_handler, #{action => login_page}},
            {"/api/trackers/create", floaty_handler, #{action => create_tracker}},
            {"/api/trackers/delete", floaty_handler, #{action => delete_tracker}},
            {"/api/:slug/total", floaty_handler, #{action => get_total}},
            {"/api/:slug/events", floaty_handler, #{action => get_events}},
            {"/api/:slug/add", floaty_handler, #{action => add_value}},
            {"/api/:slug/subtract", floaty_handler, #{action => subtract_value}},
            {"/api/:slug/delete", floaty_handler, #{action => delete_event}},
            {"/api/:slug/edit", floaty_handler, #{action => edit_event}},
            {"/:slug", floaty_handler, #{action => serve_tracker}},
            {"/", floaty_handler, #{action => serve_index}}
        ]}
    ]),
    
    % Start Cowboy HTTP server
    {ok, _} = cowboy:start_clear(http_listener,
        [{port, Port}],
        #{env => #{dispatch => Dispatch}}
    ),
    
    io:format("Server starting on port ~p~n", [Port]),
    
    floaty_erl_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
