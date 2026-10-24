# Static musl build in an empty image: just the binary. TLS roots are compiled in.
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/webhook-simulator /webhook-simulator
ENV ADDR=0.0.0.0:8080 DATABASE_PATH=/data/simulator.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/webhook-simulator"]
