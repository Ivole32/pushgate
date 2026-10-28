# Base images are pinned by digest. (No "# syntax=" line: that would pull an unpinned
# BuildKit frontend image on every build.) Update both tag and digest together (see README "Updating").
ARG BUILD_IMAGE=node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8

# ---- dependencies (production only, from the lockfile, no install scripts) ----
FROM ${BUILD_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force
COPY src ./src
COPY public ./public
# COPY keeps the permission bits of the checkout. A checkout made with a strict umask (077) would
# leave files readable only by root, so normalise: owned by root, world-readable, not writable
# by the runtime user.
RUN chown -R 0:0 /app \
 && chmod -R u=rwX,go=rX /app \
 && mkdir -p -m 700 /out/data

# ---- runtime: distroless, no shell, no package manager, non-root (uid 65532) ----
FROM ${RUNTIME_IMAGE}
WORKDIR /app
ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning \
    PORT=8080 \
    DATA_DIR=/data
COPY --from=deps /app /app
# Empty, non-root-owned data directory: a new named volume inherits this ownership.
COPY --from=deps --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/nodejs/bin/node", "src/healthcheck.js"]
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["src/server.js"]
