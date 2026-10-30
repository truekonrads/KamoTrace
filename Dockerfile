# KamoTrace with all Python dependencies. Suzaku (AGPL-3.0) and MaxMind GeoLite2 (EULA) are not
# included: fetch Suzaku at run time with `kamotrace get-suzaku`, and mount your own GeoLite2 folder.
FROM python:3.12-slim-trixie AS build
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/kamotrace UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim-trixie
COPY --from=build /opt/kamotrace /opt/kamotrace
# KAMOTRACE_BIND lets Docker publish the port; publish it on the host's 127.0.0.1 only.
ENV PATH=/opt/kamotrace/bin:$PATH KAMOTRACE_BIND=0.0.0.0 KAMOTRACE_TOOLS=/tools HOME=/home/kamotrace
# World-writable so `docker run --user "$(id -u):$(id -g)"` works with Linux bind mounts too.
RUN useradd --uid 10001 --create-home kamotrace && mkdir -p /case /tools && chmod 1777 /case /tools /home/kamotrace
USER kamotrace
WORKDIR /case
VOLUME ["/tools"]
EXPOSE 8765
ENTRYPOINT ["kamotrace"]
CMD ["--help"]
