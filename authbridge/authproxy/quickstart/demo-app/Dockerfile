FROM golang:1.26-alpine AS builder

WORKDIR /app

# Initialize go module for demo app
RUN go mod init demo-app

# Copy source code first to analyze dependencies
COPY main.go .

# Add required dependencies
RUN go get github.com/lestrrat-go/jwx/v2/jwk github.com/lestrrat-go/jwx/v2/jwt

# Download dependencies (go.sum will be created automatically)
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o target .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/target .

EXPOSE 8081 8443

CMD ["./target"]
