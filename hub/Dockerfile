# Build stage
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /websub-hub

# Final stage
FROM alpine:3.18

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /websub-hub /websub-hub

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["/websub-hub"]