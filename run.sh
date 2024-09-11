#!/bin/bash
BTC_START_HEIGHT=1625
local() {
    rm -rf .sid/logs/
    rm -rf .sid/data/
    go run cmd/sid/main.go start --start-height ${BTC_START_HEIGHT} --home .sid --params-path ./global-params.json
}

$@