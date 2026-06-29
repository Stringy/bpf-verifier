# Stage 1: Build and test.
FROM rust:bookworm AS builder

# System deps: clang (BPF target + build.rs), F* installer deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld libbpf-dev \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install F* (includes Z3 and ulib)
RUN curl -fsSL https://aka.ms/install-fstar | bash -s -- --release
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /build
COPY . .

# Verify F* modules
RUN make check-obj check-ast test-ast

# Build and test the Rust binary
RUN cargo build --release --bin bpf-verifier
RUN cargo test --release


# Stage 2: Minimal runtime image.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# F* (installed to /root/.local by the installer in stage 1)
COPY --from=builder /root/.local/ /root/.local/
ENV PATH="/root/.local/bin:${PATH}"

# bpf-verifier binary
COPY --from=builder /build/target/release/bpf-verifier /usr/local/bin/

# Verified F* modules (with .checked files from make check-obj/check-ast)
COPY --from=builder /build/fstar/ /usr/local/share/bpf-verifier/fstar/

WORKDIR /work
ENTRYPOINT ["bpf-verifier"]
