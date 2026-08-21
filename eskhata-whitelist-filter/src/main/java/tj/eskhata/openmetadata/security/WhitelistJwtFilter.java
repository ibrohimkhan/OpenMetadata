/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;
import org.openmetadata.schema.api.security.AuthenticationConfiguration;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;
import org.openmetadata.schema.auth.LoginRequest;
import org.openmetadata.schema.exception.JsonParsingException;
import org.openmetadata.schema.utils.JsonUtils;
import org.openmetadata.service.security.AuthServeletHandler;
import org.openmetadata.service.security.AuthServeletHandlerRegistry;
import org.openmetadata.service.security.JwtFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Restricts who may log in to OpenMetadata, on top of the stock {@link JwtFilter}.
 *
 * <p>Plugged in through AUTHORIZER_REQUEST_FILTER, which OpenMetadata instantiates by reflection
 * using the (AuthenticationConfiguration, AuthorizerConfiguration) constructor.
 *
 * <p>Login reaches the server by two different routes and both are covered:
 *
 * <ul>
 *   <li>POST /api/v1/users/login — a JAX-RS resource, so this filter sees it directly;
 *   <li>POST /api/v1/auth/login — a servlet wired straight into Jetty, which no JAX-RS filter can
 *       observe. It is covered by {@link GuardedAuthServletHandler}, installed into
 *       AuthServeletHandlerRegistry.
 * </ul>
 *
 * <p>The guard is re-checked on every request because OpenMetadata replaces the registry handler
 * after this filter is constructed, and again whenever security configuration is reloaded.
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class WhitelistJwtFilter extends JwtFilter {
  private static final Logger LOG = LoggerFactory.getLogger(WhitelistJwtFilter.class);

  private static final String LOGIN_PATH = "v1/users/login";
  private static final String WHITELIST_FILE_VARIABLE = "ESKHATA_LOGIN_WHITELIST_FILE";
  private static final String DEFAULT_WHITELIST_FILE =
      "/data/openmetadata/config/login-whitelist.txt";
  private static final String DENIAL_TEMPLATE = "{\"code\":403,\"message\":\"%s\"}";

  private static final Object GUARD_LOCK = new Object();

  private final LoginPolicy policy;

  public WhitelistJwtFilter(
      final AuthenticationConfiguration authenticationConfiguration,
      final AuthorizerConfiguration authorizerConfiguration) {
    super(authenticationConfiguration, authorizerConfiguration);
    this.policy =
        new LoginPolicy(
            new LoginWhitelist(whitelistFile()),
            adminPrincipalsOf(authorizerConfiguration),
            new OpenMetadataUsers());
    LOG.info("Login whitelist filter active, list file: {}", whitelistFile());
    installServletGuard();
  }

  @Override
  public void filter(final ContainerRequestContext requestContext) {
    installServletGuard();
    if (isLoginRequest(requestContext)) {
      applyPolicy(requestContext);
    } else {
      super.filter(requestContext);
    }
  }

  private void applyPolicy(final ContainerRequestContext requestContext) {
    final LoginDecision decision = policy.decide(principalOf(requestContext));
    if (decision.isAllowed()) {
      super.filter(requestContext);
    } else {
      requestContext.abortWith(denial(requestContext));
    }
  }

  /**
   * OpenMetadata overwrites the registry handler on startup and on every security reload, so the
   * guard is reinstalled rather than assumed to be in place.
   */
  private void installServletGuard() {
    if (!(AuthServeletHandlerRegistry.getHandler() instanceof GuardedAuthServletHandler)) {
      synchronized (GUARD_LOCK) {
        final AuthServeletHandler current = AuthServeletHandlerRegistry.getHandler();
        if (!(current instanceof GuardedAuthServletHandler)) {
          AuthServeletHandlerRegistry.setHandler(new GuardedAuthServletHandler(current, policy));
          LOG.info("Whitelist guard installed in front of {}", current.getClass().getSimpleName());
        }
      }
    }
  }

  private static boolean isLoginRequest(final ContainerRequestContext requestContext) {
    return LOGIN_PATH.equalsIgnoreCase(requestContext.getUriInfo().getPath());
  }

  private static String principalOf(final ContainerRequestContext requestContext) {
    String principal = null;
    final String body = readBody(requestContext);
    if (body != null) {
      principal = emailFrom(body);
    }
    return principal;
  }

  /** Reads the body and puts it back, so the resource method downstream still sees it. */
  private static String readBody(final ContainerRequestContext requestContext) {
    String body = null;
    try {
      final byte[] bytes = requestContext.getEntityStream().readAllBytes();
      requestContext.setEntityStream(new ByteArrayInputStream(bytes));
      body = new String(bytes, StandardCharsets.UTF_8);
    } catch (IOException e) {
      LOG.error("Could not read the login request body: {}", e.getMessage());
    }
    return body;
  }

  private static String emailFrom(final String body) {
    String email = null;
    try {
      final LoginRequest login = JsonUtils.readValue(body, LoginRequest.class);
      if (login != null) {
        email = login.getEmail();
      }
    } catch (JsonParsingException e) {
      LOG.warn("Login request body is not valid JSON; denying.");
    }
    return email;
  }

  private static Response denial(final ContainerRequestContext requestContext) {
    final String language = requestContext.getHeaderString(HttpHeaders.ACCEPT_LANGUAGE);
    return Response.status(Response.Status.FORBIDDEN)
        .type(MediaType.APPLICATION_JSON)
        .entity(String.format(DENIAL_TEMPLATE, DenialMessages.forAcceptLanguage(language)))
        .build();
  }

  private static Set<String> adminPrincipalsOf(final AuthorizerConfiguration configuration) {
    Set<String> admins = Set.of();
    if (configuration != null && configuration.getAdminPrincipals() != null) {
      admins =
          configuration.getAdminPrincipals().stream()
              .map(Principals::normalize)
              .collect(Collectors.toUnmodifiableSet());
    }
    return admins;
  }

  private static Path whitelistFile() {
    final String configured = System.getenv(WHITELIST_FILE_VARIABLE);
    return Path.of(configured == null || configured.isBlank() ? DEFAULT_WHITELIST_FILE : configured);
  }
}
