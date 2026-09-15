FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 collector && mkdir -p /workspace && chown collector:collector /workspace
USER collector
WORKDIR /workspace
ENTRYPOINT ["xsscollect"]
CMD ["doctor"]

