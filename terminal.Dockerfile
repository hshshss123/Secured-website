FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl git python3 python3-pip jq \
    iproute2 iputils-ping dnsutils net-tools procps file \
    nmap netcat-openbsd openssl wget less vim-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash lab && \
    printf 'lab ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/lab 2>/dev/null || true

USER lab
WORKDIR /home/lab
ENV HOME=/home/lab
CMD ["/bin/bash", "--login"]
