FROM rust:latest

ENV DOCKER_VERSION=18.03.0-ce
RUN curl -fsSLO "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" \
        && mv "docker-${DOCKER_VERSION}.tgz" docker.tgz \
        && tar xzvf docker.tgz \
        && mv docker/docker /usr/local/bin \
        && rm -r docker docker.tgz

ENV DOCKERCOMPOSE_VERSION=1.20.1
RUN curl -fsSL -o /usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/${DOCKERCOMPOSE_VERSION}/docker-compose-Linux-x86_64" \
        && chmod +x /usr/local/bin/docker-compose
