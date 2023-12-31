FROM golang:1.20-alpine

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
ENV CGO_ENABLED=0
RUN go build -v -ldflags="-s -w" -o arkime-supervisor

FROM ubuntu:22.04

ENV VER=4.6.1

RUN apt update && \
    apt install -y curl wget libwww-perl libjson-perl ethtool libyaml-dev jq libmagic1 iproute2 liblua5.4-0 libmaxminddb0 libpcap0.8 libglib2.0-0 libyara8 librdkafka1 && \
    rm -rf /var/lib/apt/lists/* && \
    curl hhttps://github.com/arkime/arkime/releases/download/v$VER/arkime_$VER-1.ubuntu2204_amd64.deb -o /opt/arkime_$VER-1_amd64.deb && \
    dpkg -i /opt/arkime_$VER-1_amd64.deb && \
    rm /opt/arkime_$VER-1_amd64.deb


COPY --from=0 /go/src/app/arkime-supervisor /opt/arkime/

EXPOSE 8005

WORKDIR /opt/arkime

ENTRYPOINT ["./arkime-supervisor"]
