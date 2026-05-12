FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy go mod and go sum files
COPY go.mod go.sum ./

# Download dependencies (go.sum will be created automatically if missing)
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-proxy .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/auth-proxy .

EXPOSE 8080

CMD ["./auth-proxy"]
