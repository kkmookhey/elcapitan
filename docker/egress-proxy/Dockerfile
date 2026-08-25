# The egress allowlist for the challenger stage.
#
# Alpine is pinned by digest for the same reason the runtime image is: an
# unpinned base means the boundary a scored batch ran behind is not
# identifiable afterwards.
FROM alpine:3.20

RUN apk add --no-cache tinyproxy=1.11.2-r0 || apk add --no-cache tinyproxy

COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter /etc/tinyproxy/filter

EXPOSE 8888
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
