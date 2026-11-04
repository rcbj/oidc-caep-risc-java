# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM maven:3.9-eclipse-temurin-26 AS test
# TrustChainTest runs the install script's trust-chain code, which is Python.
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Both modules: library/ (the published library) and demo/ (the demo, and
# TrustChainTest, which runs scripts/ against demo/oidc.json).
COPY pom.xml .
COPY library library
COPY demo/pom.xml demo/pom.xml
COPY demo/src demo/src
COPY scripts scripts
COPY demo/oidc.json demo/oidc.json
RUN mvn -B test

FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY library library
COPY demo/pom.xml demo/pom.xml
COPY demo/src demo/src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:17-jre
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The demo module's runnable jar (the demo, the library and its dependencies),
# under the name the image has always run.
COPY --from=build /src/demo/target/oidc-caep-risc-demo-0.2.0.jar /app/oidc-caep-risc.jar
COPY scripts scripts
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch. Rebuild after running the
# install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the client
# secret or a key). A COPY of the demo DIRECTORY succeeds with or without it,
# so a fresh clone and CI still build; naming the file, or a glob that
# matches nothing, fails the build in both builders.
COPY demo demo
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["java", "-jar", "/app/oidc-caep-risc.jar"]
