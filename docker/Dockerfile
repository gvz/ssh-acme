FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-client \
        libpam0g \
    && rm -rf /var/lib/apt/lists/*

COPY ssh-ca-server_*.deb /tmp/
COPY ssh-ca-client_*.deb /tmp/

# Install both packages with dpkg directly, skipping the postinst
# systemctl calls which are not available inside a container.
RUN dpkg --unpack /tmp/ssh-ca-server_*.deb /tmp/ssh-ca-client_*.deb && \
    rm -f /var/lib/dpkg/info/ssh-ca-server.postinst && \
    dpkg --configure ssh-ca-server ssh-ca-client && \
    rm -f /tmp/*.deb

# Generate default keys (can be overridden by mounting a volume)
RUN mkdir -p /etc/ssh_ca_server/hosts && \
    ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ssh_ca_host_ed25519_key -N "" -C "ssh_ca_host" && \
    chmod 600 /etc/ssh_ca_server/ssh_ca_host_ed25519_key && \
    ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ca_key -N "" -C "ssh_ca" && \
    chmod 600 /etc/ssh_ca_server/ca_key

EXPOSE 2222

ENTRYPOINT ["/usr/bin/ssh_ca_server"]
CMD ["-c", "/etc/ssh_ca_server/config.toml"]
