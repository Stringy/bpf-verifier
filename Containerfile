# Stage 1: Build F* from source.
#
# F* is an OCaml project — we use the official opam image, clone the
# pinned commit, install dependencies, and compile. This stage is slow
# (~10-15 min) but Docker layer-caches it.
FROM ocaml/opam:debian-12-ocaml-5.3 AS fstar-builder

ARG FSTAR_COMMIT=2c2435aa539cb36a6b111e4a23435556c5122d62

# System dependencies for F* build and Z3 download
RUN sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    curl unzip ca-certificates git make m4 pkg-config libgmp-dev \
    && sudo rm -rf /var/lib/apt/lists/*

# Clone F* at the pinned commit
RUN git clone --depth 1 https://github.com/FStarLang/FStar.git /home/opam/fstar-src \
    && cd /home/opam/fstar-src \
    && git fetch --depth 1 origin "$FSTAR_COMMIT" \
    && git checkout "$FSTAR_COMMIT"

WORKDIR /home/opam/fstar-src

# Install Z3 (F*'s own script handles version pinning)
RUN sudo bash .scripts/get_fstar_z3.sh /usr/local/bin

# Install F* via opam from the cloned source. This builds the
# compiler, standard library, and Pulse plugin in one step.
RUN opam install -y ./fstar.opam

# Collect F* artifacts into a known location for the next stage.
# opam puts the binary in the switch bin; ulib is in the source tree.
RUN sudo mkdir -p /fstar-dist/bin /fstar-dist/lib \
    && sudo cp "$(opam var bin)/fstar.exe" /fstar-dist/bin/ \
    && sudo cp -r ulib /fstar-dist/lib/fstar

# Stage 2: Build the Rust binary.
FROM rust:bookworm AS rust-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY build.rs build.rs
COPY templates/ templates/
COPY askama.toml askama.toml

RUN cargo build --release

# Stage 3: Minimal runtime image with all tools.
FROM debian:bookworm-slim

# System packages: clang (BPF target), BPF headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld \
    libbpf-dev linux-headers-generic \
    make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# F* and Z3
COPY --from=fstar-builder /fstar-dist/bin/fstar.exe /usr/local/bin/
COPY --from=fstar-builder /fstar-dist/lib/fstar/ /usr/local/lib/fstar/
COPY --from=fstar-builder /usr/local/bin/z3-* /usr/local/bin/
ENV FSTAR_HOME=/usr/local/lib/fstar

# bpf-verifier binary
COPY --from=rust-builder /build/target/release/bpf-verifier /usr/local/bin/

# F* verification modules (both object-level and AST-level)
COPY fstar/ /usr/local/share/bpf-verifier/fstar/

WORKDIR /work
ENTRYPOINT ["bpf-verifier"]
