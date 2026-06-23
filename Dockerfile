FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scep-intune ./cmd/scep-intune

FROM gcr.io/distroless/static:nonroot
COPY --from=build /scep-intune /scep-intune
USER nonroot:nonroot
ENTRYPOINT ["/scep-intune", "-config", "/etc/scep/config.yaml"]
