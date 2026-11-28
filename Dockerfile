# Native builds stay in the builder; the runtime needs no compiler or package setup.
FROM rust:1.100.0-slim-trixie AS rust
FROM python:3.14-slim-trixie AS build
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /usr/local/bin/uv
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/kamotrace \
    UV_PYTHON_INSTALL_DIR=/opt/python CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup \
    PATH=/opt/kamotrace/bin:/usr/local/cargo/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable
# These installers verify exact revisions, locked native builds and synthetic
# forensic/native-reader contracts, and retain source, licences and receipts.
RUN kamotrace get-iwatobi --dest /opt/tools
RUN kamotrace get-tracequarry --dest /opt/tools
# The release ZIP omits the binary's AGPL notice; retain its matching source too.
RUN kamotrace get-suzaku --version 3.0.0 --dest /tools \
    && git clone --depth 1 --branch v3.0.0 https://github.com/Yamato-Security/suzaku.git /opt/tools/suzaku-source-3.0.0 \
    && test "$(git -C /opt/tools/suzaku-source-3.0.0 rev-parse HEAD)" = c88eca3a03227a0d9a55d59a1c45677315cf4fc8 \
    && git -C /opt/tools/suzaku-source-3.0.0 rev-parse HEAD > /opt/tools/suzaku-source-3.0.0/kamotrace-source-revision \
    && rm -rf /opt/tools/suzaku-source-3.0.0/.git /opt/tools/suzaku-source-3.0.0/test_files/mmdb \
    && cp /opt/tools/suzaku-source-3.0.0/LICENSE.txt /tools/suzaku-3.0.0/LICENSE.txt \
    && chmod -R a+rX /opt/tools /opt/python /tools

FROM python:3.14-slim-trixie
COPY --from=build /opt/kamotrace /opt/kamotrace
COPY --from=build /opt/tools /opt/tools
COPY --from=build /opt/python /opt/python
COPY --from=build /tools /tools
RUN ln -s /opt/tools/iwatobi-d4b5f02cbd7fe7a044f8a5e1153157355489bd5b/iwatobi /usr/local/bin/iwatobi \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/tools/tracequarry-26c941fb575347c055f79a1c10ed68ba9bdb8a2d/venv/bin/python "$@"' > /usr/local/bin/tracequarry-python \
    && chmod 755 /usr/local/bin/tracequarry-python
# KAMOTRACE_BIND lets Docker publish the port; publish it on the host's 127.0.0.1 only.
ENV PATH=/opt/kamotrace/bin:$PATH KAMOTRACE_BIND=0.0.0.0 KAMOTRACE_TOOLS=/tools HOME=/home/kamotrace \
    TRACEQUARRY_JOURNAL_READER=/opt/tools/tracequarry-26c941fb575347c055f79a1c10ed68ba9bdb8a2d/tracequarry-journal-reader
# World-writable so `docker run --user "$(id -u):$(id -g)"` works with Linux bind mounts too.
RUN useradd --uid 10001 --create-home kamotrace && mkdir -p /case /tools \
    && chown -R kamotrace:kamotrace /tools && chmod 1777 /case /tools /home/kamotrace
USER kamotrace
WORKDIR /case
VOLUME ["/case", "/tools"]
EXPOSE 8765
# Python handles SIGINT and closes the Store; SIGTERM's default would bypass cleanup.
STOPSIGNAL SIGINT
ENTRYPOINT ["kamotrace"]
CMD ["serve", "--case", "/case/case.json"]
