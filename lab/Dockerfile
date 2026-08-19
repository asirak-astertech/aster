ARG LAB_BASE_IMAGE=rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97

FROM ${LAB_BASE_IMAGE} AS build
ENV PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p aster-lab -p aster-ip --bins

FROM ${LAB_BASE_IMAGE} AS runtime
ENV PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
COPY lab/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        iproute2 \
        iputils-ping \
        nftables \
        procps \
        tcpdump \
    && install -d -m 0755 /usr/share/aster-lab \
    && dpkg-query -W -f='${binary:Package}\t${Version}\n' \
        iproute2 iputils-ping nftables procps tcpdump \
        > /usr/share/aster-lab/runtime-package-inventory.tsv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /work/target/release/aster-lab /usr/local/bin/aster-lab
COPY --from=build /work/target/release/aster-relay /usr/local/bin/aster-relay
COPY LICENSE /usr/share/licenses/aster/LICENSE
ENTRYPOINT ["/usr/local/bin/aster-lab"]
