ARG BUILDPLATFORM="linux/amd64"
ARG BUILDERIMAGE="golang:1.19-bullseye"
# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
ARG BASEIMAGE="golang:1.19-bullseye"

FROM --platform=$BUILDPLATFORM $BUILDERIMAGE as builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""
ARG LDFLAGS

ENV GO111MODULE=on \
    CGO_ENABLED=1 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOARM=${TARGETVARIANT}

WORKDIR /go/src/github.com/open-policy-agent/gatekeeper

COPY pkg/ pkg/
COPY third_party/ third_party/
COPY vendor/ vendor/
COPY main.go main.go
COPY apis/ apis/
COPY go.mod .
COPY go.sum .

RUN go build -mod vendor -a -ldflags "${LDFLAGS:--X github.com/open-policy-agent/gatekeeper/pkg/version.Version=latest}" -o manager main.go

FROM $BASEIMAGE

WORKDIR /

COPY wasm/ hackathon/gatekeeper/wasm/
COPY --from=builder /go/src/github.com/open-policy-agent/gatekeeper/manager .

RUN chown -R 1000:999 hackathon

USER 1000:999

ENTRYPOINT ["/manager"]
