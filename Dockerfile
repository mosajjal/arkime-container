FROM golang:1.17-alpine

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
ENV CGO_ENABLED=0
RUN go build -v -ldflags="-s -w" -o arkime-supervisor

FROM ubuntu:20.04

ENV VER=3.4.1

RUN apt update && \
    apt install -y curl wget libwww-perl libjson-perl ethtool libyaml-dev jq libmagic1 iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    curl https://s3.amazonaws.com/files.molo.ch/builds/ubuntu-20.04/arkime_$VER-1_amd64.deb -o /opt/arkime_$VER-1_amd64.deb && \
    dpkg -i /opt/arkime_$VER-1_amd64.deb && \
    rm /opt/arkime_$VER-1_amd64.deb


COPY --from=0 /go/src/app/arkime-supervisor /opt/arkime/

EXPOSE 8005

WORKDIR /opt/arkime

ENTRYPOINT ["./arkime-supervisor"]
