# Build Geth in a stock Go builder container
FROM golang:1.13-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git

ADD . /Elastos.ELA.SideChain.ESC
RUN cd /Elastos.ELA.SideChain.ESC && make geth bootnode

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /Elastos.ELA.SideChain.ESC/build/bin/* /usr/local/bin/

EXPOSE 20636 20635 8547 20638 20638/udp
#ENTRYPOINT ["geth"]
