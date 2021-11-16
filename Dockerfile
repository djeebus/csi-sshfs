FROM golang:1.12-alpine3.9 AS  build-env
RUN apk add --no-cache git

ENV CGO_ENABLED=0, GO111MODULE=on
WORKDIR /go/src/github.com/nlemeshko/csi-sshfs

ADD . /go/src/github.com/nlemeshko/csi-sshfs

RUN go mod download
RUN export BUILD_TIME=`date -R` && \
    export VERSION=`cat /go/src/github.com/nlemeshko/csi-sshfs/version.txt 2&> /dev/null` && \
    go build -o /csi-sshfs -ldflags "-X 'github.com/nlemeshko/csi-sshfs/pkg/sshfs.BuildTime=${BUILD_TIME}' -X 'github.com/chr-fritz/nlemeshko/pkg/sshfs.Version=${VERSION}'" github.com/nlemeshko/csi-sshfs/cmd/csi-sshfs

FROM alpine:3.9

RUN apk add --no-cache ca-certificates sshfs findmnt

COPY --from=build-env /csi-sshfs /bin/csi-sshfs

ENTRYPOINT ["/bin/csi-sshfs"]
CMD [""]