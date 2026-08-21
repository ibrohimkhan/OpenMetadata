#!/usr/bin/env python3
"""Render the stand's docker-compose.yml from the upstream one shipped in the offline kit.

Two edits, both asserted to apply the expected number of times so that an upstream
change fails the build loudly instead of shipping a half-patched file:

  1. LDAP block  -> uncommented and completed, in both services
  2. server only -> volumes for the filter jar and the whitelist file, plus
                    EXT_CLASSPATH and ESKHATA_LOGIN_WHITELIST_FILE

This mirrors what openmetadata/offline/lib/transform_compose.py does in the
superset-ai-pilot repo; it lives here until the edits are folded into that script.

Usage: render-compose.py <upstream-compose.yml> <output.yml>
"""

from __future__ import annotations

import sys

LDAP_OLD = """      # For LDAP Authentication
      # AUTHENTICATION_LDAP_HOST: ${AUTHENTICATION_LDAP_HOST:-}
      # AUTHENTICATION_LDAP_PORT: ${AUTHENTICATION_LDAP_PORT:-}
      # AUTHENTICATION_LOOKUP_ADMIN_DN: ${AUTHENTICATION_LOOKUP_ADMIN_DN:-""}
      # AUTHENTICATION_LOOKUP_ADMIN_PWD: ${AUTHENTICATION_LOOKUP_ADMIN_PWD:-""}
      # AUTHENTICATION_USER_LOOKUP_BASEDN: ${AUTHENTICATION_USER_LOOKUP_BASEDN:-""}
      # AUTHENTICATION_USER_MAIL_ATTR: ${AUTHENTICATION_USER_MAIL_ATTR:-}
      # AUTHENTICATION_LDAP_POOL_SIZE: ${AUTHENTICATION_LDAP_POOL_SIZE:-3}
      # AUTHENTICATION_LDAP_SSL_ENABLED: ${AUTHENTICATION_LDAP_SSL_ENABLED:-}
      # AUTHENTICATION_LDAP_TRUSTSTORE_TYPE: ${AUTHENTICATION_LDAP_TRUSTSTORE_TYPE:-TrustAll}
      # AUTHENTICATION_LDAP_TRUSTSTORE_PATH: ${AUTHENTICATION_LDAP_TRUSTSTORE_PATH:-}
      # AUTHENTICATION_LDAP_KEYSTORE_PASSWORD: ${AUTHENTICATION_LDAP_KEYSTORE_PASSWORD:-}
      # AUTHENTICATION_LDAP_SSL_KEY_FORMAT: ${AUTHENTICATION_LDAP_SSL_KEY_FORMAT:-}
      # AUTHENTICATION_LDAP_ALLOW_WILDCARDS: ${AUTHENTICATION_LDAP_ALLOW_WILDCARDS:-}
      # AUTHENTICATION_LDAP_ALLOWED_HOSTNAMES: ${AUTHENTICATION_LDAP_ALLOWED_HOSTNAMES:-[]}
      # AUTHENTICATION_LDAP_SSL_VERIFY_CERT_HOST: ${AUTHENTICATION_LDAP_SSL_VERIFY_CERT_HOST:-}
      # AUTHENTICATION_LDAP_EXAMINE_VALIDITY_DATES: ${AUTHENTICATION_LDAP_EXAMINE_VALIDITY_DATES:-true}
"""

LDAP_NEW = """      # For LDAP Authentication
      AUTHENTICATION_LDAP_HOST: ${AUTHENTICATION_LDAP_HOST:-}
      AUTHENTICATION_LDAP_PORT: ${AUTHENTICATION_LDAP_PORT:-389}
      AUTHENTICATION_LOOKUP_ADMIN_DN: ${AUTHENTICATION_LOOKUP_ADMIN_DN:-""}
      AUTHENTICATION_LOOKUP_ADMIN_PWD: ${AUTHENTICATION_LOOKUP_ADMIN_PWD:-""}
      AUTHENTICATION_USER_LOOKUP_BASEDN: ${AUTHENTICATION_USER_LOOKUP_BASEDN:-""}
      AUTHENTICATION_GROUP_LOOKUP_BASEDN: ${AUTHENTICATION_GROUP_LOOKUP_BASEDN:-""}
      AUTHENTICATION_USER_MAIL_ATTR: ${AUTHENTICATION_USER_MAIL_ATTR:-userPrincipalName}
      AUTHENTICATION_USER_NAME_ATTR: ${AUTHENTICATION_USER_NAME_ATTR:-sAMAccountName}
      # Quoted on purpose: a bare * reaches openmetadata.yaml as a YAML alias
      # and the server fails to start.
      AUTHENTICATION_USER_ALL_ATTR: ${AUTHENTICATION_USER_ALL_ATTR:-"*"}
      AUTHENTICATION_USER_GROUP_ATTR: ${AUTHENTICATION_USER_GROUP_ATTR:-objectClass}
      AUTHENTICATION_USER_GROUP_ATTR_VALUE: ${AUTHENTICATION_USER_GROUP_ATTR_VALUE:-group}
      AUTHENTICATION_USER_GROUP_MEMBER_ATTR: ${AUTHENTICATION_USER_GROUP_MEMBER_ATTR:-member}
      AUTHENTICATION_USER_ROLE_ADMIN_NAME: ${AUTHENTICATION_USER_ROLE_ADMIN_NAME:-admin}
      # Quoted on purpose: authRolesMapping is a JSON string, not a YAML mapping.
      AUTH_ROLES_MAPPING: ${AUTH_ROLES_MAPPING:-"{}"}
      AUTH_REASSIGN_ROLES: ${AUTH_REASSIGN_ROLES:-[]}
      AUTHENTICATION_LDAP_POOL_SIZE: ${AUTHENTICATION_LDAP_POOL_SIZE:-3}
      AUTHENTICATION_LDAP_SSL_ENABLED: ${AUTHENTICATION_LDAP_SSL_ENABLED:-false}
      AUTHENTICATION_LDAP_TRUSTSTORE_TYPE: ${AUTHENTICATION_LDAP_TRUSTSTORE_TYPE:-TrustAll}
      AUTHENTICATION_LDAP_TRUSTSTORE_PATH: ${AUTHENTICATION_LDAP_TRUSTSTORE_PATH:-}
      AUTHENTICATION_LDAP_KEYSTORE_PASSWORD: ${AUTHENTICATION_LDAP_KEYSTORE_PASSWORD:-}
      AUTHENTICATION_LDAP_SSL_KEY_FORMAT: ${AUTHENTICATION_LDAP_SSL_KEY_FORMAT:-}
      AUTHENTICATION_LDAP_ALLOW_WILDCARDS: ${AUTHENTICATION_LDAP_ALLOW_WILDCARDS:-}
      AUTHENTICATION_LDAP_ALLOWED_HOSTNAMES: ${AUTHENTICATION_LDAP_ALLOWED_HOSTNAMES:-[]}
      AUTHENTICATION_LDAP_SSL_VERIFY_CERT_HOST: ${AUTHENTICATION_LDAP_SSL_VERIFY_CERT_HOST:-}
      AUTHENTICATION_LDAP_EXAMINE_VALIDITY_DATES: ${AUTHENTICATION_LDAP_EXAMINE_VALIDITY_DATES:-true}
"""

HEAP_OLD = """      # Heap OPTS Configurations
      OPENMETADATA_HEAP_OPTS: ${OPENMETADATA_HEAP_OPTS:--Xmx1G -Xms1G}"""

HEAP_NEW = """      # Extra jars appended to the classpath by openmetadata-server-start.sh.
      EXT_CLASSPATH: ${EXT_CLASSPATH:-}
      # Read by the Eskhata login whitelist filter.
      ESKHATA_LOGIN_WHITELIST_FILE: ${ESKHATA_LOGIN_WHITELIST_FILE:-/data/openmetadata/config/login-whitelist.txt}

      # Heap OPTS Configurations
      OPENMETADATA_HEAP_OPTS: ${OPENMETADATA_HEAP_OPTS:--Xmx1G -Xms1G}"""

EXPOSE_OLD = """    expose:
      - 8585
      - 8586
    ports:
      - "${OM_HOST_PORT:-8585}:8585\""""

EXPOSE_NEW = """    volumes:
      # Mounted 1:1 so the path reads the same on the host and in the container.
      - /data/openmetadata/ext:/data/openmetadata/ext:ro
      - /data/openmetadata/config:/data/openmetadata/config:ro
    expose:
      - 8585
      - 8586
    ports:
      - "${OM_HOST_PORT:-8585}:8585\""""

EDITS = [
    ("LDAP block", LDAP_OLD, LDAP_NEW, 2),
    ("classpath and whitelist env", HEAP_OLD, HEAP_NEW, 2),
    ("server volumes", EXPOSE_OLD, EXPOSE_NEW, 1),
]


def render(text: str) -> str:
    for label, old, new, expected in EDITS:
        found = text.count(old)
        if found != expected:
            raise SystemExit(
                f"ERROR: {label}: expected {expected} match(es), found {found}. "
                "Upstream compose changed; update this script."
            )
        text = text.replace(old, new)
    return text


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        rendered = render(handle.read())
    with open(argv[2], "w", encoding="utf-8") as handle:
        handle.write(rendered)
    print(f"render-compose: wrote {argv[2]} ({len(EDITS)} edits applied)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
