# Stage 1: Build F* from source.
#
# F* is an OCaml project — we use the official opam image, clone the
# pinned commit, install dependencies, and compile. This stage is slow
# (~10-15 min) but the layer is cached.
FROM ocaml/opam:debian-12-ocaml-5.3 AS fstar-builder

ARG FSTAR_COMMIT=2c2435aa539cb36a6b111e4a23435556c5122d62

RUN sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    curl unzip ca-certificates git make m4 pkg-config libgmp-dev \
    && sudo rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/FStarLang/FStar.git /home/opam/fstar-src \
    && cd /home/opam/fstar-src \
    && git fetch --depth 1 origin "$FSTAR_COMMIT" \
    && git checkout "$FSTAR_COMMIT"

WORKDIR /home/opam/fstar-src

RUN sudo bash .scripts/get_fstar_z3.sh /usr/local/bin
RUN opam install -y ./fstar.opam

RUN sudo mkdir -p /fstar-dist/bin /fstar-dist/lib \
    && sudo cp "$(opam var bin)/fstar.exe" /fstar-dist/bin/ \
    && sudo cp -r ulib /fstar-dist/lib/fstar


# Stage 2: Build and test the Rust binary.
#
# Needs clang for build.rs (compiles BPF test corpus).
FROM rust:bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs askama.toml ./
COPY src/ src/
COPY templates/ templates/
COPY tests/ tests/
COPY include/ include/

RUN cargo build --release --bin bpf-verifier
RUN cargo test --release


# Stage 3: Verify F* modules.
#
# Runs fstar.exe on both object-level and AST-level modules.
# This validates the verification infrastructure itself.
FROM debian:bookworm-slim AS fstar-check

COPY --from=fstar-builder /fstar-dist/bin/fstar.exe /usr/local/bin/
COPY --from=fstar-builder /fstar-dist/lib/fstar/ /usr/local/lib/fstar/
COPY --from=fstar-builder /usr/local/bin/z3-* /usr/local/bin/
ENV FSTAR_HOME=/usr/local/lib/fstar

WORKDIR /check
COPY fstar/ fstar/
COPY Makefile .

RUN make check-ast test-ast


# Stage 4: Minimal runtime image.
#
# Contains only what's needed to run bpf-verifier:
# - The binary
# - F* and Z3 (for verification)
# - Clang (for AST mode: C source → JSON AST)
# - BPF headers (for clang -target bpf)
# - The F* verification modules
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# F* and Z3
COPY --from=fstar-builder /fstar-dist/bin/fstar.exe /usr/local/bin/
COPY --from=fstar-builder /fstar-dist/lib/fstar/ /usr/local/lib/fstar/
COPY --from=fstar-builder /usr/local/bin/z3-* /usr/local/bin/
ENV FSTAR_HOME=/usr/local/lib/fstar

# bpf-verifier binary (from the tested build)
COPY --from=rust-builder /build/target/release/bpf-verifier /usr/local/bin/

# F* verification modules (validated by fstar-check stage)
COPY --from=fstar-check /check/fstar/ /usr/local/share/bpf-verifier/fstar/

WORKDIR /work
ENTRYPOINT ["bpf-verifier"]
