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


# Stage 2: Build and test everything.
#
# Has clang (for build.rs BPF compilation), F* and Z3 (for corpus tests).
# All Rust tests run here including the corpus integration tests.
FROM rust:bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# F* and Z3 from stage 1 so corpus tests can run
COPY --from=fstar-builder /fstar-dist/bin/fstar.exe /usr/local/bin/
COPY --from=fstar-builder /fstar-dist/lib/fstar/ /usr/local/lib/fstar/
COPY --from=fstar-builder /usr/local/bin/z3-* /usr/local/bin/
ENV FSTAR_HOME=/usr/local/lib/fstar

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs askama.toml ./
COPY src/ src/
COPY templates/ templates/
COPY tests/ tests/
COPY include/ include/
COPY fstar/ fstar/
COPY Makefile .

# Pre-verify the object-level F* modules so the corpus tests don't
# have to re-check them on every invocation.
RUN make check-obj

RUN cargo build --release --bin bpf-verifier
RUN cargo test --release


# Stage 3: Verify F* modules.
#
# Validates the AST-level verification infrastructure.
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
# Only the binary, F*/Z3, clang, and verified F* modules.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm lld \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=fstar-builder /fstar-dist/bin/fstar.exe /usr/local/bin/
COPY --from=fstar-builder /fstar-dist/lib/fstar/ /usr/local/lib/fstar/
COPY --from=fstar-builder /usr/local/bin/z3-* /usr/local/bin/
ENV FSTAR_HOME=/usr/local/lib/fstar

COPY --from=rust-builder /build/target/release/bpf-verifier /usr/local/bin/
COPY --from=fstar-check /check/fstar/ /usr/local/share/bpf-verifier/fstar/

WORKDIR /work
ENTRYPOINT ["bpf-verifier"]
