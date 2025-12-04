FROM alpine:3.18

# Install required tools
RUN apk add --no-cache \
    bash \
    grep \
    findutils \
    git \
    curl \
    jq

# Copy scanner scripts
COPY entrypoint.sh /entrypoint.sh
COPY patterns.json /patterns.json

# Make scripts executable
RUN chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
