# Copyright Pit Kleyersburg <pitkley@googlemail.com>
# SPDX-License-Identifier: MIT OR Apache-2.0

# Stage 0: builder image
FROM rust:latest as builder

COPY . /app

WORKDIR /app
RUN set -ex ;\
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-musl' ;; \
        armhf) rustArch='armv7-unknown-linux-musleabihf' ;; \
        arm64) rustArch='aarch64-unknown-linux-musl' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    rustup target add "$rustArch" ;\
    cargo build --target "$rustArch" --release ;\
    cargo test --target "$rustArch" --release -- --nocapture ;\
    mv target/"$rustArch"/release/dfw dfw ;\
    :

# Stage 1: final image
FROM alpine

RUN apk add --no-cache \
    iptables \
    ip6tables \
    nftables \
    ;

COPY --from=builder /app/dfw /dfw
ENTRYPOINT ["/dfw"]
