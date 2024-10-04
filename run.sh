#!/bin/bash
BTC_START_HEIGHT=1
local() {
    if [ -n "$ENV" ]; then
        echo "ENV is set to $ENV"
    else
        echo "ENV is not set"
        echo "Set default ENV to local"
        ENV=local
    fi
    rm -rf .sid/logs/
    rm -rf .sid/data/

    mkdir .sid
    # cp ../config/indexer-${ENV}.conf .sid/sid.conf
    
    go run cmd/sid/main.go start --start-height ${BTC_START_HEIGHT} --home .sid --params-path ./global-params.json
}

dev() {
    echo "Starting staking-indexer in debug mode"
    if [ -n "$ENV" ]; then
        echo "ENV is set to $ENV"
    else
        echo "ENV is not set"
        echo "Set default ENV to local"
        ENV=local
    fi

    rm -rf .sid

    mkdir .sid

    cp ../config/staking-indexer/${ENV}/sid.conf .sid/sid.conf
    # cp ../config/indexer-global-params-${ENV}.json global-params.json

    # find bitcoind:18332 in .sid/sid.conf and replace with localhost:18332
    find ./.sid/sid.conf -type f -print0 | xargs -0 sed -i '' "s#bitcoind:18332#localhost:18332#g"

    # replace db path /home/staking-indexer/ with ./
    find ./.sid/sid.conf -type f -print0 | xargs -0 sed -i '' "s#/home/staking-indexer/#./#g"

    # replace rabbitmq:5672 to localhost:15672
    find ./.sid/sid.conf -type f -print0 | xargs -0 sed -i '' "s#rabbitmq:5672#localhost:5672#g"

    go run cmd/sid/main.go start --start-height ${BTC_START_HEIGHT} --home .sid --params-path ./global-params.json
}

$@

