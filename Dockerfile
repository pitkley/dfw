# Stage 0: builder image
FROM ekidd/rust-musl-builder:stable as builder

COPY . /home/rust/src

RUN set -ex ;\
    cargo build --target x86_64-unknown-linux-musl --release ;\
    cargo test --target x86_64-unknown-linux-musl --release -- --nocapture ;\
    :

# Stage 1: final image
FROM alpine

RUN apk add --no-cache \
    iptables \
    ip6tables \
    nftables \
    ;

COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/dfw /dfw
ENTRYPOINT ["/dfw"]

