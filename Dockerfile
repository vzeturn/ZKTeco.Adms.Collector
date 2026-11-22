# ADMS attendance collector -- generic container image (optional; the documented hosting is IIS
# on-premises, see the README).
#
#   * adms.hosting.serve binds a host/port from the CLI/env and runs waitress. Under IIS the Python
#     process listens on loopback behind IIS. In a container there is no IIS in front, so this image
#     binds 0.0.0.0 directly. Restrict who can reach the port with your container network or firewall
#     (allow only the device subnet).
#   * The DPAPI/registry connection-string path (adms.dbconfig) is Windows-only and is not imported in
#     this image. Supply ADMS_SQL_CONNECTION as an environment variable from your orchestrator's secret
#     store. See adms/config.py's resolve_connection_string for the fallback chain.
#   * Logging writes structured JSON to stdout (adms.logging_setup.JsonLogger); ADMS_LOG_DIR is left
#     unset so nothing writes a log file inside the container's ephemeral filesystem.
#
# Base image: python:3.12-slim (Debian). Not alpine: pyodbc needs a glibc-linked ODBC driver, and
# Microsoft ships msodbcsql18 for Debian/Ubuntu, not musl.

FROM python:3.12-slim AS base

# ---- ODBC Driver 18 for SQL Server ------------------------------------------------------------
# Same driver the Windows install docs name (deploy/install-iis.ps1 checks for it); this is Microsoft's
# own apt repository for Debian 12 ("bookworm", which python:3.12-slim is built on).
# libgssapi-krb5-2 is not pulled in automatically by msodbcsql18's own dependency list on
# Debian 12, but the driver's shared object (libmsodbcsql-18.6.so.*) is dynamically linked
# against libgssapi_krb5.so.2 for Kerberos support -- without it, unixODBC's driver manager
# reports the confusing "Can't open lib ... file not found" even though the .so file itself is
# present, because dlopen() fails to resolve one of *its* dependencies, and unixODBC does not
# surface that distinction. Verified with `ldd` against the installed driver.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        ca-certificates \
        unixodbc \
        libgssapi-krb5-2 \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# ---- Optional: Amazon RDS CA bundle -------------------------------------------------------
# The connection string sets TrustServerCertificate=no (adms.config.build_connection_string defaults
# to validating the server certificate), so the client needs a trust chain to whatever CA signed the
# database server's certificate. This step trusts the Amazon RDS global bundle, the container
# equivalent of deploy/import-rds-ca.ps1. Remove it, or replace it with your own CA, if your SQL
# Server is not on Amazon RDS.
RUN curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
        -o /usr/local/share/ca-certificates/rds-global-bundle.crt \
    && update-ca-certificates \
    && apt-get purge -y gnupg curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Python dependencies ----------------------------------------------------------------------
# requirements.txt holds exact pins only (pyodbc, waitress, and the Sentry SDK) -- see the file's own
# comment for why that is deliberate. Nothing dev-only (ruff/mypy/pytest) ships in the image.
COPY requirements.txt ./
RUN pip install --no-cache-dir --no-compile -r requirements.txt

# ---- Application code -------------------------------------------------------------------------
COPY src/ ./src/

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Non-root: the ADMS endpoint is unauthenticated by protocol design (see the README's security
# section), so the container that terminates it should hold no more privilege than it needs to bind a
# port and open outbound ODBC/HTTPS connections.
RUN useradd --system --no-create-home --uid 10001 adms
USER adms

EXPOSE 80

# Port 80, not adms.hosting.serve's own CLI default of 8080: the ZKTeco ADMS/PUSH protocol speaks plain
# HTTP on port 80 by firmware design, and in a container this process is the direct listener.
#
# --host 0.0.0.0 is required: the module's own CLI default is 127.0.0.1, correct behind IIS and wrong
# for a bare container.
#
# Binding port 80 as the non-root `adms` user normally fails with EACCES, because Linux reserves ports
# below 1024. Either lower the reservation for the container (for example
# `--sysctl net.ipv4.ip_unprivileged_port_start=0`) or publish a high port and map it to 80 outside
# the container.
ENTRYPOINT ["python", "-m", "adms.hosting.serve", "--host", "0.0.0.0", "--port", "80"]
