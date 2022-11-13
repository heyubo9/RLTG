FROM ubuntu:18.04

# TODO remove sudo for user "magma" to avoid unwanted priv escalation from
# other attack vectors.

RUN apt-get update && apt-get install -y sudo bison flex texinfo libbz2-dev vim liblzo2-dev

RUN  sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list

COPY ./ /RLTG/

USER root:root
RUN /RLTG/preinstall.sh
RUN /RLTG/build.sh

ENV CC /RLTG/afl-clang-fast
ENV CXX /RLTG/afl-clang-fast++
ENV AFLGO /RLTG/
ENV AFL_NO_AFFINITY 1

WORKDIR /RLTG