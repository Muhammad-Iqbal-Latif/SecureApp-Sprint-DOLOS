FROM python:3.13-slim AS native-builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY native/secure.c .
RUN gcc -O2 -fPIC -shared -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DDOLOS_LIBRARY -o libdolos_native.so secure.c

FROM python:3.13-slim
# Remediate inherited Python dependency vulnerabilities
RUN python -m pip install --no-cache-dir \
    msgpack==1.2.3 \
    setuptools==84.2.1 \
    urllib3==2.8.0 \
    && python -m pip check
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DOLOS_HOST=0.0.0.0 DOLOS_PORT=5000 DOLOS_DB=/app/instance/dolos.sqlite3
WORKDIR /app
RUN groupadd --system dolos && useradd --system --gid dolos --home /app dolos
COPY --chown=dolos:dolos dolos ./dolos
COPY --from=native-builder --chown=dolos:dolos /build/libdolos_native.so ./native/libdolos_native.so
COPY --chown=dolos:dolos run.py .
RUN mkdir -p /app/instance && chown dolos:dolos /app/instance
USER dolos
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD python -c "from urllib.request import urlopen; assert urlopen('http://127.0.0.1:5000/health',timeout=2).status==200"
CMD ["python", "run.py"]
