%%%-------------------------------------------------------------------
%% @doc HTTP request handler for floaty
%% @end
%%%-------------------------------------------------------------------

-module(floaty_handler).

-export([init/2]).

-define(EVENT_MANUAL, <<"manual">>).
-define(EVENT_METADATA, <<"metadata">>).

%% ===================================================================
%% Cowboy Handler Callbacks
%% ===================================================================

init(Req0, State) ->
    Method = cowboy_req:method(Req0),
    Action = maps:get(action, State),
    {ok, NoAuth} = application:get_env(floaty_erl, no_auth),
    
    Req = case NoAuth of
        true ->
            handle_action(Method, Action, Req0);
        false ->
            case Action of
                login_page when Method =:= <<"POST">> ->
                    handle_login(Req0);
                login_page ->
                    serve_login(Req0);
                _ ->
                    case check_auth(Req0) of
                        {ok, authenticated} ->
                            handle_action(Method, Action, Req0);
                        {error, unauthorized} ->
                            Req1 = cowboy_req:reply(303, #{
                                <<"location">> => <<"/login">>
                            }, Req0),
                            Req1
                    end
            end
    end,
    {ok, Req, State}.

%% ===================================================================
%% Authentication
%% ===================================================================

check_auth(Req) ->
    case cowboy_req:parse_cookies(Req) of
        #{<<"floaty_session">> := SessionToken} ->
            case ets:lookup(sessions, SessionToken) of
                [{SessionToken, true}] ->
                    {ok, authenticated};
                _ ->
                    {error, unauthorized}
            end;
        _ ->
            {error, unauthorized}
    end.

serve_login(Req) ->
    % Check if already logged in
    case check_auth(Req) of
        {ok, authenticated} ->
            cowboy_req:reply(303, #{<<"location">> => <<"/">>}, Req);
        {error, unauthorized} ->
            {ok, Html} = file:read_file("templates/login.html"),
            cowboy_req:reply(200, #{
                <<"content-type">> => <<"text/html">>
            }, Html, Req)
    end.

handle_login(Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    case jsx:decode(Body, [return_maps]) of
        #{<<"username">> := Username, <<"password">> := Password} ->
            {ok, AppUsername} = application:get_env(floaty_erl, username),
            {ok, AppPassword} = application:get_env(floaty_erl, password),
            
            case {Username, Password} of
                {AppUsername, AppPassword} ->
                    SessionToken = generate_session_token(),
                    ets:insert(sessions, {SessionToken, true}),
                    
                    {ok, CookieMaxAge} = application:get_env(floaty_erl, cookie_max_age),
                    
                    Req2 = cowboy_req:set_resp_cookie(<<"floaty_session">>, SessionToken, Req1, #{
                        path => <<"/">>,
                        max_age => CookieMaxAge,
                        http_only => true,
                        same_site => strict
                    }),
                    
                    Resp = jsx:encode(#{<<"status">> => <<"success">>}),
                    cowboy_req:reply(200, #{
                        <<"content-type">> => <<"application/json">>
                    }, Resp, Req2);
                _ ->
                    cowboy_req:reply(401, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Invalid credentials">>, Req1)
            end;
        _ ->
            cowboy_req:reply(400, #{
                <<"content-type">> => <<"text/plain">>
            }, <<"Invalid request">>, Req1)
    end.

generate_session_token() ->
    Bytes = crypto:strong_rand_bytes(32),
    Hash = crypto:hash(sha256, Bytes),
    binary:encode_hex(Hash).

%% ===================================================================
%% Route Handlers
%% ===================================================================

handle_action(<<"GET">>, serve_index, Req) ->
    case load_trackers() of
        {ok, Trackers} ->
            {ok, Template} = file:read_file("templates/index.html"),
            Html = render_index(Template, Trackers),
            cowboy_req:reply(200, #{
                <<"content-type">> => <<"text/html">>
            }, Html, Req);
        {error, _} ->
            cowboy_req:reply(500, #{
                <<"content-type">> => <<"text/plain">>
            }, <<"Failed to load trackers">>, Req)
    end;

handle_action(<<"GET">>, serve_tracker, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_slug(Slug) of
        false ->
            cowboy_req:reply(400, #{
                <<"content-type">> => <<"text/plain">>
            }, <<"Invalid slug format">>, Req);
        true ->
            LogFile = get_log_file(Slug),
            case filelib:is_file(LogFile) of
                false ->
                    serve_404(Req);
                true ->
                    case get_tracker(Slug) of
                        {ok, Tracker} ->
                            {ok, Template} = file:read_file("templates/tracker.html"),
                            Html = render_tracker(Template, Tracker),
                            cowboy_req:reply(200, #{
                                <<"content-type">> => <<"text/html">>
                            }, Html, Req);
                        {error, _} ->
                            serve_404(Req)
                    end
            end
    end;

handle_action(<<"POST">>, create_tracker, Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    case jsx:decode(Body, [return_maps]) of
        #{<<"title">> := Title, <<"slug">> := Slug} when Title =/= <<>>, Slug =/= <<>> ->
            case validate_slug(Slug) of
                false ->
                    cowboy_req:reply(400, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Invalid slug format (lowercase letters, numbers, hyphens only)">>, Req1);
                true ->
                    LogFile = get_log_file(Slug),
                    case filelib:is_file(LogFile) of
                        true ->
                            cowboy_req:reply(409, #{
                                <<"content-type">> => <<"text/plain">>
                            }, <<"Tracker already exists">>, Req1);
                        false ->
                            Timestamp = erlang:system_time(millisecond),
                            Metadata = #{
                                <<"id">> => generate_id(),
                                <<"timestamp">> => Timestamp,
                                <<"type">> => ?EVENT_METADATA,
                                <<"note">> => Title
                            },
                            case append_event(Slug, Metadata) of
                                ok ->
                                    Response = #{
                                        <<"title">> => Title,
                                        <<"slug">> => Slug,
                                        <<"created">> => Timestamp
                                    },
                                    cowboy_req:reply(201, #{
                                        <<"content-type">> => <<"application/json">>
                                    }, jsx:encode(Response), Req1);
                                {error, _} ->
                                    cowboy_req:reply(500, #{
                                        <<"content-type">> => <<"text/plain">>
                                    }, <<"Failed to create tracker">>, Req1)
                            end
                    end
            end;
        _ ->
            cowboy_req:reply(400, #{
                <<"content-type">> => <<"text/plain">>
            }, <<"Title and slug are required">>, Req1)
    end;

handle_action(<<"POST">>, delete_tracker, Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    case jsx:decode(Body, [return_maps]) of
        #{<<"slug">> := Slug} ->
            LogFile = get_log_file(Slug),
            case file:delete(LogFile) of
                ok ->
                    Response = #{<<"status">> => <<"deleted">>},
                    cowboy_req:reply(200, #{
                        <<"content-type">> => <<"application/json">>
                    }, jsx:encode(Response), Req1);
                {error, _} ->
                    cowboy_req:reply(500, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Failed to delete tracker">>, Req1)
            end;
        _ ->
            cowboy_req:reply(400, #{
                <<"content-type">> => <<"text/plain">>
            }, <<"Slug is required">>, Req1)
    end;

handle_action(<<"GET">>, get_total, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_and_check_slug(Slug) of
        {error, Response} ->
            Response(Req);
        ok ->
            case load_events(Slug) of
                {ok, Events} ->
                    Total = calculate_total(Events),
                    Response = #{<<"total">> => Total},
                    cowboy_req:reply(200, #{
                        <<"content-type">> => <<"application/json">>
                    }, jsx:encode(Response), Req);
                {error, _} ->
                    cowboy_req:reply(500, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Failed to load events">>, Req)
            end
    end;

handle_action(<<"GET">>, get_events, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_and_check_slug(Slug) of
        {error, Response} ->
            Response(Req);
        ok ->
            case load_events(Slug) of
                {ok, Events} ->
                    cowboy_req:reply(200, #{
                        <<"content-type">> => <<"application/json">>
                    }, jsx:encode(Events), Req);
                {error, _} ->
                    cowboy_req:reply(500, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Failed to load events">>, Req)
            end
    end;

handle_action(<<"POST">>, add_value, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_and_check_slug(Slug) of
        {error, Response} ->
            Response(Req);
        ok ->
            {ok, Body, Req1} = cowboy_req:read_body(Req),
            case jsx:decode(Body, [return_maps]) of
                #{<<"value">> := Value} = EventData ->
                    Note = maps:get(<<"note">>, EventData, <<>>),
                    Event = #{
                        <<"id">> => generate_id(),
                        <<"timestamp">> => erlang:system_time(millisecond),
                        <<"type">> => ?EVENT_MANUAL,
                        <<"value">> => Value,
                        <<"note">> => Note
                    },
                    case append_event(Slug, Event) of
                        ok ->
                            cowboy_req:reply(201, #{
                                <<"content-type">> => <<"application/json">>
                            }, jsx:encode(Event), Req1);
                        {error, _} ->
                            cowboy_req:reply(500, #{
                                <<"content-type">> => <<"text/plain">>
                            }, <<"Failed to add value">>, Req1)
                    end;
                _ ->
                    cowboy_req:reply(400, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Invalid request">>, Req1)
            end
    end;

handle_action(<<"POST">>, subtract_value, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_and_check_slug(Slug) of
        {error, Response} ->
            Response(Req);
        ok ->
            {ok, Body, Req1} = cowboy_req:read_body(Req),
            case jsx:decode(Body, [return_maps]) of
                #{<<"value">> := Value} = EventData ->
                    Note = maps:get(<<"note">>, EventData, <<>>),
                    Event = #{
                        <<"id">> => generate_id(),
                        <<"timestamp">> => erlang:system_time(millisecond),
                        <<"type">> => ?EVENT_MANUAL,
                        <<"value">> => -Value,
                        <<"note">> => Note
                    },
                    case append_event(Slug, Event) of
                        ok ->
                            cowboy_req:reply(201, #{
                                <<"content-type">> => <<"application/json">>
                            }, jsx:encode(Event), Req1);
                        {error, _} ->
                            cowboy_req:reply(500, #{
                                <<"content-type">> => <<"text/plain">>
                            }, <<"Failed to subtract value">>, Req1)
                    end;
                _ ->
                    cowboy_req:reply(400, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Invalid request">>, Req1)
            end
    end;

handle_action(<<"POST">>, delete_event, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_and_check_slug(Slug) of
        {error, Response} ->
            Response(Req);
        ok ->
            {ok, Body, Req1} = cowboy_req:read_body(Req),
            case jsx:decode(Body, [return_maps]) of
                #{<<"id">> := EventId} ->
                    Event = #{
                        <<"id">> => EventId,
                        <<"timestamp">> => erlang:system_time(millisecond),
                        <<"deleted">> => true
                    },
                    case append_event(Slug, Event) of
                        ok ->
                            Response = #{<<"status">> => <<"deleted">>},
                            cowboy_req:reply(200, #{
                                <<"content-type">> => <<"application/json">>
                            }, jsx:encode(Response), Req1);
                        {error, _} ->
                            cowboy_req:reply(500, #{
                                <<"content-type">> => <<"text/plain">>
                            }, <<"Failed to delete event">>, Req1)
                    end;
                _ ->
                    cowboy_req:reply(400, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Invalid request">>, Req1)
            end
    end;

handle_action(<<"POST">>, edit_event, Req) ->
    Slug = cowboy_req:binding(slug, Req),
    case validate_and_check_slug(Slug) of
        {error, Response} ->
            Response(Req);
        ok ->
            {ok, Body, Req1} = cowboy_req:read_body(Req),
            case jsx:decode(Body, [return_maps]) of
                #{<<"id">> := EditedId, <<"value">> := Value} = EventData ->
                    Note = maps:get(<<"note">>, EventData, <<>>),
                    Event = #{
                        <<"id">> => generate_id(),
                        <<"timestamp">> => erlang:system_time(millisecond),
                        <<"type">> => ?EVENT_MANUAL,
                        <<"value">> => Value,
                        <<"note">> => Note,
                        <<"edited_id">> => EditedId
                    },
                    case append_event(Slug, Event) of
                        ok ->
                            cowboy_req:reply(200, #{
                                <<"content-type">> => <<"application/json">>
                            }, jsx:encode(Event), Req1);
                        {error, _} ->
                            cowboy_req:reply(500, #{
                                <<"content-type">> => <<"text/plain">>
                            }, <<"Failed to edit event">>, Req1)
                    end;
                _ ->
                    cowboy_req:reply(400, #{
                        <<"content-type">> => <<"text/plain">>
                    }, <<"Invalid request">>, Req1)
            end
    end;

handle_action(_, _, Req) ->
    cowboy_req:reply(405, #{
        <<"content-type">> => <<"text/plain">>
    }, <<"Method not allowed">>, Req).

%% ===================================================================
%% Helper Functions
%% ===================================================================

serve_404(Req) ->
    case file:read_file("templates/404.html") of
        {ok, Html} ->
            cowboy_req:reply(404, #{
                <<"content-type">> => <<"text/html">>
            }, Html, Req);
        {error, _} ->
            cowboy_req:reply(404, #{
                <<"content-type">> => <<"text/plain">>
            }, <<"404 - Page Not Found">>, Req)
    end.

validate_slug(Slug) ->
    case re:run(Slug, "^[a-z0-9-]+$") of
        {match, _} when byte_size(Slug) > 0, byte_size(Slug) =< 50 ->
            true;
        _ ->
            false
    end.

validate_and_check_slug(Slug) ->
    case validate_slug(Slug) of
        false ->
            {error, fun(Req) ->
                cowboy_req:reply(400, #{
                    <<"content-type">> => <<"text/plain">>
                }, <<"Invalid slug format">>, Req)
            end};
        true ->
            LogFile = get_log_file(Slug),
            case filelib:is_file(LogFile) of
                false ->
                    {error, fun serve_404/1};
                true ->
                    ok
            end
    end.

get_log_file(Slug) ->
    filename:join(["data", <<Slug/binary, ".log">>]).

load_trackers() ->
    filelib:ensure_dir("data/"),
    case file:list_dir("data") of
        {ok, Files} ->
            Trackers = lists:filtermap(fun(File) ->
                case filename:extension(File) of
                    ".log" ->
                        Slug = list_to_binary(filename:basename(File, ".log")),
                        case get_tracker(Slug) of
                            {ok, Tracker} ->
                                {true, Tracker};
                            {error, _} ->
                                false
                        end;
                    _ ->
                        false
                end
            end, Files),
            
            % Sort by creation time
            SortedTrackers = lists:sort(fun(A, B) ->
                maps:get(<<"created">>, A) =< maps:get(<<"created">>, B)
            end, Trackers),
            
            {ok, SortedTrackers};
        {error, Reason} ->
            {error, Reason}
    end.

get_tracker(Slug) ->
    LogFile = get_log_file(Slug),
    case file:open(LogFile, [read, binary]) of
        {ok, File} ->
            try
                case file:read_line(File) of
                    {ok, Line} ->
                        Event = jsx:decode(Line, [return_maps]),
                        case maps:get(<<"type">>, Event) of
                            ?EVENT_METADATA ->
                                {ok, Events} = load_events(Slug),
                                Total = calculate_total(Events),
                                {ok, #{
                                    <<"title">> => maps:get(<<"note">>, Event),
                                    <<"slug">> => Slug,
                                    <<"created">> => maps:get(<<"timestamp">>, Event),
                                    <<"total">> => Total
                                }};
                            _ ->
                                {ok, #{
                                    <<"title">> => Slug,
                                    <<"slug">> => Slug
                                }}
                        end;
                    eof ->
                        {ok, #{
                            <<"title">> => Slug,
                            <<"slug">> => Slug
                        }}
                end
            after
                file:close(File)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

load_events(Slug) ->
    LogFile = get_log_file(Slug),
    case file:read_file(LogFile) of
        {ok, Content} ->
            Lines = binary:split(Content, <<"\n">>, [global, trim]),
            AllEvents = lists:filtermap(fun(Line) ->
                try
                    Event = jsx:decode(Line, [return_maps]),
                    case maps:get(<<"type">>, Event, undefined) of
                        ?EVENT_METADATA -> false;
                        _ -> {true, Event}
                    end
                catch
                    _:_ -> false
                end
            end, Lines),
            
            % Process deletions and edits
            Events = process_events(AllEvents),
            {ok, Events};
        {error, enoent} ->
            {ok, []};
        {error, Reason} ->
            {error, Reason}
    end.

process_events(AllEvents) ->
    % Build maps for efficient lookup
    EventMap = maps:from_list([{maps:get(<<"id">>, E), E} || E <- AllEvents]),
    DeletedIds = maps:from_list([{maps:get(<<"id">>, E), true} || E <- AllEvents, 
                                  maps:get(<<"deleted">>, E, false)]),
    
    % Build edit chain map
    EditMap = maps:from_list([{maps:get(<<"edited_id">>, E), maps:get(<<"id">>, E)} 
                              || E <- AllEvents, maps:is_key(<<"edited_id">>, E)]),
    
    % Find original timestamps
    OriginalTimestamps = lists:foldl(fun(Event, Acc) ->
        HasEditedId = maps:is_key(<<"edited_id">>, Event),
        IsDeleted = maps:get(<<"deleted">>, Event, false),
        case {HasEditedId, IsDeleted} of
            {false, false} ->
                Id = maps:get(<<"id">>, Event),
                Timestamp = maps:get(<<"timestamp">>, Event),
                maps:put(Id, Timestamp, Acc);
            _ ->
                Acc
        end
    end, #{}, AllEvents),
    
    % Follow edit chains to preserve original timestamps
    OriginalTimestamps2 = maps:fold(fun(OriginalId, FirstEditId, Acc) ->
        case maps:find(OriginalId, EventMap) of
            {ok, OrigEvent} ->
                OrigTimestamp = maps:get(<<"timestamp">>, OrigEvent),
                follow_chain(FirstEditId, EditMap, OrigTimestamp, Acc);
            error ->
                Acc
        end
    end, OriginalTimestamps, EditMap),
    
    % Build final events
    FinalEvents = lists:foldl(fun(Event, Acc) ->
        Id = maps:get(<<"id">>, Event),
        IsDeleted = maps:get(<<"deleted">>, Event, false),
        IsEdit = maps:is_key(<<"edited_id">>, Event),
        
        if
            IsDeleted orelse IsEdit ->
                Acc;
            true ->
                maps:put(Id, Event, Acc)
        end
    end, #{}, AllEvents),
    
    % Replace original events with their final edited versions
    FinalEvents2 = maps:fold(fun(OriginalId, FirstEditId, Acc) ->
        FinalId = find_final_in_chain(FirstEditId, EditMap),
        case maps:find(FinalId, EventMap) of
            {ok, FinalEvent} ->
                OrigTimestamp = maps:get(FinalId, OriginalTimestamps2, 
                                        maps:get(<<"timestamp">>, FinalEvent)),
                UpdatedEvent = maps:put(<<"timestamp">>, OrigTimestamp, FinalEvent),
                Acc1 = maps:remove(OriginalId, Acc),
                maps:put(FinalId, UpdatedEvent, Acc1);
            error ->
                Acc
        end
    end, FinalEvents, EditMap),
    
    % Filter out deleted events and convert to list
    Events = [E || {Id, E} <- maps:to_list(FinalEvents2), 
                   not maps:is_key(Id, DeletedIds)],
    Events.

follow_chain(CurrentId, EditMap, OrigTimestamp, Acc) ->
    Acc1 = maps:put(CurrentId, OrigTimestamp, Acc),
    case maps:find(CurrentId, EditMap) of
        {ok, NextId} ->
            follow_chain(NextId, EditMap, OrigTimestamp, Acc1);
        error ->
            Acc1
    end.

find_final_in_chain(CurrentId, EditMap) ->
    case maps:find(CurrentId, EditMap) of
        {ok, NextId} ->
            find_final_in_chain(NextId, EditMap);
        error ->
            CurrentId
    end.

append_event(Slug, Event) ->
    LogFile = get_log_file(Slug),
    Json = jsx:encode(Event),
    file:write_file(LogFile, [Json, <<"\n">>], [append]).

calculate_total(Events) ->
    lists:foldl(fun(Event, Total) ->
        Value = maps:get(<<"value">>, Event, 0),
        Total + Value
    end, 0, Events).

generate_id() ->
    Bytes = crypto:strong_rand_bytes(16),
    binary:encode_hex(Bytes).

%% ===================================================================
%% Template Rendering
%% ===================================================================

render_index(Template, Trackers) ->
    % Simple template rendering - replace {{trackers}} with tracker list
    TrackersHtml = lists:map(fun(Tracker) ->
        Title = maps:get(<<"title">>, Tracker),
        Slug = maps:get(<<"slug">>, Tracker),
        Total = maps:get(<<"total">>, Tracker, 0),
        io_lib:format(
            "<div class=\"tracker-card\">"
            "<a href=\"/~s\">"
            "<h2>~s</h2>"
            "<p class=\"total\">~.2f</p>"
            "</a>"
            "</div>",
            [Slug, Title, Total]
        )
    end, Trackers),
    
    % Replace placeholder in template
    binary:replace(Template, <<"{{TRACKERS}}">>, iolist_to_binary(TrackersHtml)).

render_tracker(Template, Tracker) ->
    Title = maps:get(<<"title">>, Tracker),
    Slug = maps:get(<<"slug">>, Tracker),
    
    % Replace placeholders
    Template1 = binary:replace(Template, <<"{{TITLE}}">>, Title, [global]),
    binary:replace(Template1, <<"{{SLUG}}">>, Slug, [global]).
