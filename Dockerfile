FROM scratch

COPY dfwrs /dfwrs
ENTRYPOINT ["/dfwrs"]
