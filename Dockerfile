FROM golang:1.22.3-alpine AS builder

# TARGETPLATFORM should be one of linux/amd64 or linux/arm64.
ARG TARGETPLATFORM="linux/amd64"
# Version to build. Default is empty.
ARG VERSION

# Use muslc for static libs
ARG BUILD_TAGS="muslc"

RUN apk add --no-cache --update openssh git make build-base linux-headers libc-dev \
                                pkgconfig zeromq-dev musl-dev alpine-sdk libsodium-dev \
                                libzmq-static libsodium-static gcc

# Build
WORKDIR /go/src/github.com/scalarorg/staking-indexer
# Cache dependencies
COPY go.mod go.sum /go/src/github.com/scalarorg/staking-indexer/
RUN go mod download
# Copy the rest of the files
COPY ./ /go/src/github.com/scalarorg/staking-indexer/
# If version is set, then checkout this version
RUN if [ -n "${VERSION}" ]; then \
        git checkout -f ${VERSION}; \
    fi

RUN CGO_LDFLAGS="$CGO_LDFLAGS -lstdc++ -lm -lsodium" \
    CGO_ENABLED=1 \
    BUILD_TAGS=$BUILD_TAGS \
    LINK_STATICALLY=true \
    make build

# FINAL IMAGE
FROM alpine:3.16 AS run

RUN addgroup --gid 1138 -S staking-indexer && adduser --uid 1138 -S staking-indexer -G staking-indexer

RUN apk add bash curl jq

COPY --from=builder /go/src/github.com/scalarorg/staking-indexer/build/sid /bin/sid

WORKDIR /home/staking-indexer
RUN chown -R staking-indexer /home/staking-indexer
USER staking-indexer
