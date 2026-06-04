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

# Stage 2: Minimal runtime image with all tools.
FROM debian:bookworm-slim

# System packages: clang (BPF target), make, curl (for rustup)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld \
    libbpf-dev \
    make ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# F* and Z3
COPY --from=fstar-builder /fstar-dist/bin/fstar.exe /usr/local/bin/
COPY --from=fstar-builder /fstar-dist/lib/fstar/ /usr/local/lib/fstar/
COPY --from=fstar-builder /usr/local/bin/z3-* /usr/local/bin/
ENV FSTAR_HOME=/usr/local/lib/fstar

# Rust (edition 2024 needs stable >= 1.85)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /workspace
COPY . .

CMD ["make", "test"]
