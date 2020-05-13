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
COPY --from=builder /webhook/bin/webhooksrv /server/
WORKDIR /server
RUN chmod +x webhooksrv
RUN adduser -D -g '' webhook
RUN chown -R webhook:webhook /server
USER webhook
ENTRYPOINT ["/server/webhooksrv"]
