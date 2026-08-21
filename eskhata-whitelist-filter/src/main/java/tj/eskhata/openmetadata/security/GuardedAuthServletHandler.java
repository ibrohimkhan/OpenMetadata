/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.openmetadata.schema.auth.LoginRequest;
import org.openmetadata.schema.exception.JsonParsingException;
import org.openmetadata.schema.utils.JsonUtils;
import org.openmetadata.service.security.AuthServeletHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps the handler behind POST /api/v1/auth/login and applies the whitelist before the request
 * reaches it. That endpoint is a plain servlet registered straight into Jetty, so a JAX-RS filter
 * never sees it — this decorator is how the rule reaches it.
 *
 * <p>Only POST is inspected. OIDC and SAML use GET on the same handler and carry no login body.
 */
final class GuardedAuthServletHandler implements AuthServeletHandler {
  private static final Logger LOG = LoggerFactory.getLogger(GuardedAuthServletHandler.class);

  private static final String POST_METHOD = "POST";
  private static final String ACCEPT_LANGUAGE_HEADER = "Accept-Language";
  private static final String CONTENT_TYPE_JSON = "application/json";
  private static final String MESSAGE_TEMPLATE = "{\"code\":403,\"message\":\"%s\"}";

  private final AuthServeletHandler delegate;
  private final LoginPolicy policy;

  GuardedAuthServletHandler(final AuthServeletHandler delegate, final LoginPolicy policy) {
    this.delegate = delegate;
    this.policy = policy;
  }

  AuthServeletHandler delegate() {
    return delegate;
  }

  @Override
  public void handleLogin(final HttpServletRequest req, final HttpServletResponse resp) {
    if (POST_METHOD.equalsIgnoreCase(req.getMethod())) {
      guardLogin(req, resp);
    } else {
      delegate.handleLogin(req, resp);
    }
  }

  @Override
  public void handleLogout(final HttpServletRequest req, final HttpServletResponse resp) {
    delegate.handleLogout(req, resp);
  }

  @Override
  public void handleCallback(final HttpServletRequest req, final HttpServletResponse resp) {
    delegate.handleCallback(req, resp);
  }

  @Override
  public void handleRefresh(final HttpServletRequest req, final HttpServletResponse resp) {
    delegate.handleRefresh(req, resp);
  }

  private void guardLogin(final HttpServletRequest req, final HttpServletResponse resp) {
    try {
      final CachedBodyRequest replayable = new CachedBodyRequest(req);
      applyPolicy(replayable, resp);
    } catch (IOException e) {
      LOG.error("Could not read the login request body: {}", e.getMessage());
      deny(req, resp);
    }
  }

  private void applyPolicy(final CachedBodyRequest req, final HttpServletResponse resp) {
    final LoginDecision decision = policy.decide(principalOf(req));
    if (decision.isAllowed()) {
      delegate.handleLogin(req, resp);
    } else {
      deny(req, resp);
    }
  }

  private static String principalOf(final CachedBodyRequest req) {
    String principal = null;
    try {
      final LoginRequest login = JsonUtils.readValue(req.bodyAsString(), LoginRequest.class);
      if (login != null) {
        principal = login.getEmail();
      }
    } catch (JsonParsingException e) {
      LOG.warn("Login request body is not valid JSON; denying.");
    }
    return principal;
  }

  private static void deny(final HttpServletRequest req, final HttpServletResponse resp) {
    final String message = DenialMessages.forAcceptLanguage(req.getHeader(ACCEPT_LANGUAGE_HEADER));
    resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
    resp.setContentType(CONTENT_TYPE_JSON);
    resp.setCharacterEncoding(StandardCharsets.UTF_8.name());
    try {
      resp.getWriter().write(String.format(MESSAGE_TEMPLATE, message));
    } catch (IOException e) {
      LOG.error("Could not write the denial response: {}", e.getMessage());
    }
  }
}
