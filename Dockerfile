# MeshMorphic agent image.
#
# Built from source in the first stage and copied into a scratch image in the
# second, so the shipped container holds one static binary, a certificate
# bundle, and nothing else. There is no shell in it, no package manager and no
# libc — an attacker who found a way to run something inside this container
# would find nothing to run.

FROM golang:1.23-alpine AS build

WORKDIR /src

# Dependencies first so an edit to the source does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# CGO off gives a genuinely static binary. The trimpath and ldflags settings
# strip local paths and symbols, which keeps the build reproducible: two people
# building the same commit should get byte-identical output, so that anyone can
# check a published binary really came from the published source.
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/mm-agent \
      ./cmd/mm-agent

FROM scratch

# Certificate authorities, needed to verify Let's Encrypt when requesting a
# certificate. This is the agent's only outbound trust dependency.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/mm-agent /mm-agent

# Runs unprivileged. The agent binds no privileged port: its only listener is
# the settings panel on 8800, and everything else is outbound.
USER 65532:65532

EXPOSE 8800

ENTRYPOINT ["/mm-agent", "run"]
