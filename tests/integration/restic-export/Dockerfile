FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server \
        python3 \
        rsync \
    && rm -rf /var/lib/apt/lists/*

COPY configs/70-daimon-backup-export.conf /opt/fixture/70-daimon-backup-export.conf
COPY scripts/restic-export-command.sh /opt/fixture/restic-export-command.sh
COPY scripts/restic-export-apply-disposable.py /opt/fixture/restic-export-apply-disposable.py
COPY scripts/restic-export-preflight.py /opt/fixture/restic-export-preflight.py
COPY tests/integration/restic-export/disposable-marker /opt/fixture/disposable-marker
COPY tests/integration/restic-export/sshd_config /opt/fixture/sshd_config
COPY tests/integration/restic-export/entrypoint.sh /opt/fixture/entrypoint.sh

RUN chmod 0755 \
        /opt/fixture/entrypoint.sh \
        /opt/fixture/restic-export-apply-disposable.py \
        /opt/fixture/restic-export-command.sh \
        /opt/fixture/restic-export-preflight.py

EXPOSE 2222
ENTRYPOINT ["/opt/fixture/entrypoint.sh"]
