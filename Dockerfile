FROM ubuntu:23.04

RUN apt-get update

ENV LC_ALL C.UTF-8

RUN apt-get -y install vim curl telnet iputils-ping net-tools build-essential libssl-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

ENTRYPOINT []
