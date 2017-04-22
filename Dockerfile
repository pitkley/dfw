FROM alpine

RUN apk add --no-cache iptables ip6tables

COPY dfwrs /dfwrs
ENTRYPOINT ["/dfwrs"]
