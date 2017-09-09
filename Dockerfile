FROM alpine

RUN apk add --no-cache iptables ip6tables

COPY dfw /dfw
ENTRYPOINT ["/dfw"]
