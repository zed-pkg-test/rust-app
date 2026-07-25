FROM rust:bookworm AS zed-builder

WORKDIR /src
COPY zed-interfaces ./zed-interfaces
COPY zed-cli ./zed-cli
WORKDIR /src/zed-cli
RUN cargo build --release --locked --bin zed

FROM rust:bookworm

COPY --from=zed-builder /src/zed-cli/target/release/zed /usr/local/bin/zed
WORKDIR /work
