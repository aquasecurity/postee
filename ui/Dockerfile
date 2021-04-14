FROM node:latest as vuebuilder
ADD ./frontend /frontend
WORKDIR /frontend

RUN yarn install
RUN yarn build


FROM golang:1.16-alpine as gobuilder

ADD ./backend /backend
WORKDIR /backend
RUN go build -o posteeui

FROM alpine
EXPOSE 8000

RUN mkdir /uiserver
RUN mkdir /uiserver/www

COPY --from=gobuilder /backend/posteeui /uiserver
COPY --from=vuebuilder /frontend/dist /uiserver/www

WORKDIR /uiserver

ENTRYPOINT ["/uiserver/posteeui"]