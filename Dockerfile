FROM golang:alpine as builder
RUN apk add --update make git
ADD . /webhook/
WORKDIR /webhook/
ENV GOPATH=$GOPATH:/webhook
RUN make all


FROM alpine
RUN apk update && apk add wget ca-certificates
EXPOSE 8082
EXPOSE 8445
RUN mkdir /server
RUN mkdir /server/database
RUN mkdir /config
COPY --from=builder /webhook/bin/webhooksrv /server/
COPY --from=builder /webhook/cfg.yaml /config/
WORKDIR /server
RUN chmod +x webhooksrv
RUN addgroup -g 1099 webhook
RUN adduser -D -g '' -G webhook -u 1099 webhook
RUN chown -R webhook:webhook /server
RUN chown -R webhook:webhook /config
USER webhook
ENTRYPOINT ["/server/webhooksrv"]
