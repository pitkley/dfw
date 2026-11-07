# Copyright Pit Kleyersburg <pitkley@googlemail.com>
# SPDX-License-Identifier: MIT OR Apache-2.0

# Stage 0: builder image
ARG RUST_BUILD_PLATFORM=$TARGETPLATFORM
FROM --platform=$RUST_BUILD_PLATFORM rust:latest AS builder
ARG TARGETARCH

COPY . /app

WORKDIR /app
RUN set -ex ;\
    builderArch="$(dpkg --print-architecture)"; \
    targetArch="${TARGETARCH:-$builderArch}"; \
    case "$targetArch" in \
        amd64) rustArch='x86_64-unknown-linux-musl' ;; \
        arm|armhf) rustArch='armv7-unknown-linux-musleabihf' ;; \
        arm64) rustArch='aarch64-unknown-linux-musl' ;; \
        *) echo >&2 "unsupported architecture: $targetArch"; exit 1 ;; \
    esac; \
    if [ "$rustArch" = armv7-unknown-linux-musleabihf ] && [ "$builderArch" != armhf ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends gcc-arm-linux-gnueabihf qemu-user; \
        export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=arm-linux-gnueabihf-gcc; \
        export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUNNER=qemu-arm; \
    fi; \
    rustup target add "$rustArch" ;\
    cargo build --locked --target "$rustArch" --release ;\
    cargo test --locked --target "$rustArch" --release -- --nocapture ;\
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
