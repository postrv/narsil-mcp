# Vulnerable Dockerfile - Test Fixture
# This file intentionally contains security misconfigurations for testing

# IAC-002: Using latest tag (no version pinning)
FROM ubuntu:latest

# IAC-006: Secrets in build arguments
ARG DB_PASSWORD
ARG API_SECRET_KEY
ARG AUTH_TOKEN

# IAC-006: Secrets in environment variables
ENV DATABASE_PASSWORD=PLACEHOLDER_PASSWORD_VALUE
ENV API_SECRET=PLACEHOLDER_SECRET_VALUE

# IAC-005: Using ADD instead of COPY
ADD https://example.com/archive.tar.gz /app/
ADD ./src /app/src

# IAC-004: Exposing sensitive ports
EXPOSE 22
EXPOSE 23
EXPOSE 3389
EXPOSE 5900

# Install packages (normal)
RUN apt-get update && apt-get install -y nginx

# IAC-001: Running as root (no USER directive to change)
# Container will run as root by default

CMD ["nginx", "-g", "daemon off;"]
