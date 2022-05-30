FROM golang:1.18-alpine as builder
# RUN apk add --update git
COPY . /server/
WORKDIR /server/
RUN go build -o ./bin/postee main.go

FROM alpine:3.16.0
RUN apk update && apk add wget ca-certificates curl jq
EXPOSE 8082
EXPOSE 8445
RUN mkdir /server
RUN mkdir /server/database
RUN mkdir /config

COPY --from=builder /server/bin /server/
COPY --from=builder /server/rego-templates /server/rego-templates
COPY --from=builder /server/rego-filters /server/rego-filters
COPY --from=builder /server/cfg.yaml /server/cfg.yaml
WORKDIR /server
RUN chmod +x postee
RUN addgroup -g 1099 postee
RUN adduser -D -g '' -G postee -u 1099 postee
RUN chown -R postee:postee /server
RUN chown -R postee:postee /config
USER postee
ENTRYPOINT ["/server/postee"]
