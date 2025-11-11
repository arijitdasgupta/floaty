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
    
    % Read configuration from environment variables or use defaults
    Port = get_env_int("PORT", 8080),
    NoAuth = get_env_bool("FLOATY_NO_AUTH", false),
    Username = get_env_binary("FLOATY_USERNAME", <<"admin">>),
    Password = get_env_binary("FLOATY_PASSWORD", <<"floaty">>),
    CookieMaxAge = get_env_int("FLOATY_COOKIE_MAX_AGE", 259200),
    
    % Set configuration
    application:set_env(floaty_erl, port, Port),
    application:set_env(floaty_erl, no_auth, NoAuth),
    application:set_env(floaty_erl, username, Username),
    application:set_env(floaty_erl, password, Password),
    application:set_env(floaty_erl, cookie_max_age, CookieMaxAge),
    
    % Initialize session storage ETS table
    ets:new(sessions, [named_table, public, set]),
    
    % Log authentication status
    case NoAuth of
        true -> 
            io:format("Warning: Running in NO AUTH mode. Application is publicly accessible!~n");
        false ->
            case Username of
                <<"admin">> ->
                    io:format("Warning: Using default username 'admin'. Set FLOATY_USERNAME environment variable for production.~n");
                _ -> ok
            end,
            case Password of
                <<"floaty">> ->
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

get_env_int(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Value -> 
            case string:to_integer(Value) of
                {Int, _} when is_integer(Int) -> Int;
                _ -> Default
            end
    end.

get_env_bool(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        "true" -> true;
        "false" -> false;
        _ -> Default
    end.

get_env_binary(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Value -> list_to_binary(Value)
    end.
