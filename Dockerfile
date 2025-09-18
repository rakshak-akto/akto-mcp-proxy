# syntax=docker/dockerfile:1

FROM golang:latest AS build

# Install build dependencies for tokenizers
RUN apt-get update && apt-get install -y \
    git \
    rustc \
    cargo \
    gcc \
    g++ \
    make \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set destination for COPY
WORKDIR /app

# Clone and build tokenizers library (specific version for Go package)
RUN git clone https://github.com/daulet/tokenizers /tmp/tokenizers && \
    cd /tmp/tokenizers && \
    git checkout v1.22.1 && \
    make build && \
    cp target/release/libtokenizers.a /usr/local/lib/ && \
    mkdir -p /usr/local/include && \
    cp tokenizers/src/tokenizers.h /usr/local/include/ 2>/dev/null || true

# Download and install ONNX Runtime (detect architecture) - using v1.22.0 for API version 22
RUN ARCH=$(uname -m) && \
    echo "Building for architecture: $ARCH" && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-linux-aarch64-1.22.0.tgz && \
        tar -xzf onnxruntime-linux-aarch64-1.22.0.tgz && \
        cp -r onnxruntime-linux-aarch64-1.22.0/lib/* /usr/local/lib/ && \
        cp -r onnxruntime-linux-aarch64-1.22.0/include/* /usr/local/include/ && \
        rm -rf onnxruntime-linux-aarch64-1.22.0*; \
    else \
        wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-linux-x64-1.22.0.tgz && \
        tar -xzf onnxruntime-linux-x64-1.22.0.tgz && \
        cp -r onnxruntime-linux-x64-1.22.0/lib/* /usr/local/lib/ && \
        cp -r onnxruntime-linux-x64-1.22.0/include/* /usr/local/include/ && \
        rm -rf onnxruntime-linux-x64-1.22.0*; \
    fi

# Download model files from Hugging Face (sequential to ensure both succeed)
RUN mkdir -p /app/mcp-threat/transformers/models/prompt-injection/onnx && \
    echo "Downloading model.onnx..." && \
    wget --timeout=60 --tries=3 https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model.onnx \
         -O /app/mcp-threat/transformers/models/prompt-injection/onnx/model.onnx && \
    echo "Downloading tokenizer.json..." && \
    wget --timeout=60 --tries=3 https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/tokenizer.json \
         -O /app/mcp-threat/transformers/models/prompt-injection/onnx/tokenizer.json && \
    echo "Verifying downloaded files..." && \
    ls -la /app/mcp-threat/transformers/models/prompt-injection/onnx/ && \
    test -f /app/mcp-threat/transformers/models/prompt-injection/onnx/model.onnx && \
    test -f /app/mcp-threat/transformers/models/prompt-injection/onnx/tokenizer.json && \
    echo "Both files downloaded successfully!"

# Copy go.mod only
COPY container_src/go.mod ./

# Copy container source code
COPY container_src/*.go ./

# Download dependencies and create go.sum
RUN go mod tidy

# Build with CGO enabled and link tokenizers and onnxruntime libraries
RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-extldflags '-L/usr/local/lib -ltokenizers -lonnxruntime -lstdc++ -lm'" \
    -o /server

FROM ubuntu:24.04
# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libstdc++6 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy ONNX Runtime libraries from build stage
COPY --from=build /usr/local/lib/libonnxruntime*.so* /usr/local/lib/

# Create symlink for libonnxruntime.so if it doesn't exist and update library cache
RUN cd /usr/local/lib && \
    if [ ! -f libonnxruntime.so ]; then \
        ln -sf libonnxruntime.so.1.22.0 libonnxruntime.so; \
    fi && \
    ldconfig && \
    ls -la /usr/local/lib/libonnx* || true

# Copy model files from build stage
COPY --from=build /app/mcp-threat /mcp-threat

# Verify model files are present in the final image
RUN echo "Verifying model files in runtime container:" && \
    ls -la /mcp-threat/transformers/models/prompt-injection/onnx/ || echo "Directory not found" && \
    test -f /mcp-threat/transformers/models/prompt-injection/onnx/model.onnx && echo "✓ model.onnx found" || echo "✗ model.onnx missing" && \
    test -f /mcp-threat/transformers/models/prompt-injection/onnx/tokenizer.json && echo "✓ tokenizer.json found" || echo "✗ tokenizer.json missing"

# Update library path
ENV LD_LIBRARY_PATH=/usr/local/lib

# These environment variables should be set via Cloudflare Worker/container configuration:
# - MCP_LLM_API_KEY: API key for MCP threat detection service (REQUIRED)
# - LIBONNX_RUNTIME_PATH: Path to ONNX Runtime library (optional, defaults to /usr/local/lib/libonnxruntime.so)
# - DEBUG: Set to "true" for verbose logging (optional, defaults to "false")

# Optimize for low memory environments
ENV GOGC=100
ENV GOMEMLIMIT=200MiB

# Set working directory to ensure relative paths work correctly
WORKDIR /

COPY --from=build /server /server
EXPOSE 8080

# Run
CMD ["/server"]