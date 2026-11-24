# Reference for a private pre-license staging pod only. Resolve image digest and
# locked dependencies in deployment pipeline before any production promotion.
FROM python:3.13-slim AS build
WORKDIR /build
COPY pyproject.toml ./
COPY spyderpay_core ./spyderpay_core
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir .
FROM python:3.13-slim
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SPYDERPAY_ENV=prelicense
COPY --from=build /opt/venv /opt/venv
USER 65532:65532
EXPOSE 8766
# API binds loopback by design; deploy proxy in the same network namespace.
ENTRYPOINT ["python", "-m", "spyderpay_core.postgres.api_v3"]
