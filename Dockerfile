FROM erlang:26-alpine AS builder

# Install git for fetching dependencies
RUN apk --no-cache add git

WORKDIR /app

# Copy rebar config
COPY rebar.config ./
COPY config ./config
COPY src ./src

# Get dependencies and compile
RUN rebar3 as prod compile

FROM erlang:26-alpine

WORKDIR /

# Copy compiled application
COPY --from=builder /app/_build/prod/lib ./lib
COPY static ./static
COPY templates ./templates
COPY config ./config

RUN mkdir -p /data

EXPOSE 8080

CMD ["erl", "-pa", "lib/*/ebin", "-eval", "application:ensure_all_started(floaty_erl).", "-noshell"]
