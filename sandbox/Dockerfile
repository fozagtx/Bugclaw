FROM node:22-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip curl ca-certificates git iproute2 tar && rm -rf /var/lib/apt/lists/*
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup && cp /root/.foundry/bin/* /usr/local/bin/
RUN useradd --create-home --uid 10001 runner
USER runner
WORKDIR /sandbox/work
CMD ["sleep", "infinity"]
