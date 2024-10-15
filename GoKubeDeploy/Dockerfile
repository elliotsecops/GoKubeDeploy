# Use the official Go image with Alpine as the base image
FROM golang:1.20-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go application
RUN go build -o healthcheck ./src

# Use a minimal Alpine image for the final container
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /root/

# Copy the built binary from the builder stage
COPY --from=builder /app/healthcheck /root/

# Expose the port that the application will run on
EXPOSE 8080

# Command to run the application
CMD ["./healthcheck"]
