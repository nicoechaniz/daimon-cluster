FROM python:3.13.5-slim-bookworm@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/daimon-cluster

ARG MATRIX_COMMIT
COPY constraints.txt matrix.bundle /tmp/build/
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git ca-certificates \
    && git clone --quiet /tmp/build/matrix.bundle /tmp/build/matrix \
    && python -m pip install --disable-pip-version-check \
        --constraint /tmp/build/constraints.txt \
        "daimon-matrix @ git+file:///tmp/build/matrix@${MATRIX_COMMIT}" \
        PyYAML==6.0.3 cryptography==50.0.0 \
    && apt-get purge --yes --auto-remove git \
    && rm -rf /var/lib/apt/lists/* /root/.cache/pip /tmp/build

COPY clusterctl /opt/daimon-cluster/clusterctl
COPY configs/clusterctl.yaml /opt/daimon-cluster/configs/clusterctl.yaml
COPY role.py /opt/daimon-recovery-role.py

WORKDIR /opt/daimon-cluster
