# Eskhata login whitelist filter

Restricts who may sign in to OpenMetadata to a list kept in a plain text file.

Built as a standalone module that modifies **no upstream file**, so rebasing this fork onto a
newer OpenMetadata tag never conflicts — it carries one extra directory and nothing else.

## Rules

| Situation | Result |
|---|---|
| Deleted in OpenMetadata (`deleted = true`) | denied, whatever the list says |
| Listed in `AUTHORIZER_ADMIN_PRINCIPALS` | allowed, even if absent from the file |
| Present in the whitelist file | allowed |
| Already an active OpenMetadata user | allowed |
| Anything else | denied |

Deleting a user in OpenMetadata therefore revokes access on its own — the file does not have to
be edited. Removing a line only stops a new account from being created.

If the file is missing or unreadable the list is treated as empty: people who already have an
account keep working, nobody new gets in, and the reason is logged at ERROR.

## Both login routes are covered

OpenMetadata 1.13 accepts logins on two endpoints:

- `POST /api/v1/users/login` — a JAX-RS resource, handled by `WhitelistJwtFilter` itself;
- `POST /api/v1/auth/login` — a servlet registered straight into Jetty, which no JAX-RS filter
  can see. `GuardedAuthServletHandler` wraps the registry handler to cover it.

The wrapper is reinstalled on every request, because OpenMetadata replaces the registry handler
after the filter is constructed and again whenever security configuration is reloaded.

## Build

Requires JDK 21 and Maven. `openmetadata-service` comes from Maven Central in `provided` scope,
so the rest of the fork does not have to be built.

```bash
mvn -B package
```

The jar lands in `target/eskhata-whitelist-filter-<version>.jar`.

## Deploy

Put the jar anywhere the server can read it and point the classpath at it. On the Eskhata stand
that is `/data/openmetadata/ext`, mounted 1:1 into the container.

```
AUTHORIZER_REQUEST_FILTER=tj.eskhata.openmetadata.security.WhitelistJwtFilter
EXT_CLASSPATH=/data/openmetadata/ext/eskhata-whitelist-filter-1.13.0.jar
ESKHATA_LOGIN_WHITELIST_FILE=/data/openmetadata/config/login-whitelist.txt
```

`ESKHATA_LOGIN_WHITELIST_FILE` is optional; it defaults to the path above.

Setting `AUTHORIZER_REQUEST_FILTER` back to `org.openmetadata.service.security.JwtFilter` turns
the whitelist off — that is the intended off switch, no other change needed.

**OpenMetadata reads its security configuration from the database, not from the environment**,
once the settings row exists. After changing any of these variables, clear it and recreate the
container, otherwise nothing happens:

```bash
docker exec openmetadata_server ./bootstrap/openmetadata-ops.sh remove-security-config --force
docker compose --project-name openmetadata --env-file site.env -f docker-compose.yml \
  up -d --force-recreate openmetadata-server
```

## The list file

See `login-whitelist.example.txt`. One principal per line, written exactly as the user types it
in the login form — with `AUTHENTICATION_USER_MAIL_ATTR=userPrincipalName` that is the UPN.
Blank lines and `#` comments are ignored, case and surrounding spaces do not matter.

Edits are picked up within ten seconds. Every reload logs how many entries were accepted and how
many lines were skipped or malformed, which is worth checking after editing the file by hand:

```bash
docker logs --since 2m openmetadata_server 2>&1 | grep -i whitelist
```

## Tools

`tools/render-compose.py` applies the stand's compose edits (LDAP block, mounts, classpath) to
an upstream OpenMetadata compose file. It lives here until those edits are folded into
`transform_compose.py` in the offline kit.
