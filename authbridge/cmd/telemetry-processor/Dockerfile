FROM golang:1.24-alpine AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o telemetry-processor .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/telemetry-processor /telemetry-processor
EXPOSE 9091
ENTRYPOINT ["/telemetry-processor"]
