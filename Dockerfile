# syntax=docker/dockerfile:1

FROM golang:1.21-alpine AS build

# Set destination for COPY
WORKDIR /app

# Copy go.mod only
COPY container_src/go.mod ./

# Copy container source code
COPY container_src/*.go ./

# Download dependencies and create go.sum
RUN go mod tidy

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /server /server
EXPOSE 8080

# Run
CMD ["/server"]