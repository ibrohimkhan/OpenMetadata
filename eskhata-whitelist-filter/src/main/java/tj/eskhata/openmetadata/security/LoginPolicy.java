/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import java.util.Set;
import java.util.function.Function;
import org.openmetadata.schema.entity.teams.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides whether a login attempt may reach the authentication provider.
 *
 * <p>Rules, in order:
 *
 * <ul>
 *   <li>deleted in OpenMetadata — always denied, whatever the file says, so that removing a user
 *       in the UI actually revokes access;
 *   <li>listed as an admin principal — always allowed, so a bad whitelist file cannot lock the
 *       administrators out;
 *   <li>present in the whitelist file — allowed;
 *   <li>already an active OpenMetadata user — allowed, so that turning the filter on does not cut
 *       off people who were using the system before;
 *   <li>otherwise denied.
 * </ul>
 */
final class LoginPolicy {
  private static final Logger LOG = LoggerFactory.getLogger(LoginPolicy.class);

  private final LoginWhitelist whitelist;
  private final Set<String> adminPrincipals;
  private final Function<String, User> userLookup;

  LoginPolicy(
      final LoginWhitelist whitelist,
      final Set<String> adminPrincipals,
      final Function<String, User> userLookup) {
    this.whitelist = whitelist;
    this.adminPrincipals = Set.copyOf(adminPrincipals);
    this.userLookup = userLookup;
  }

  LoginDecision decide(final String rawPrincipal) {
    final String principal = Principals.normalize(rawPrincipal);
    LoginDecision decision = LoginDecision.DENIED_UNREADABLE_REQUEST;
    if (!principal.isEmpty()) {
      decision = evaluate(principal);
      LOG.info("Login check for '{}': {}", principal, decision);
    } else {
      LOG.warn("Login request carried no principal; denying.");
    }
    return decision;
  }

  private LoginDecision evaluate(final String principal) {
    final User existing = userLookup.apply(principal);
    final LoginDecision decision;
    if (isDeleted(existing)) {
      decision = LoginDecision.DENIED_DELETED_IN_OM;
    } else if (isAdmin(principal) || whitelist.contains(principal) || existing != null) {
      decision = LoginDecision.ALLOWED;
    } else {
      decision = LoginDecision.DENIED_NOT_LISTED;
    }
    return decision;
  }

  private boolean isAdmin(final String principal) {
    return adminPrincipals.contains(Principals.localPart(principal));
  }

  private static boolean isDeleted(final User user) {
    return user != null && Boolean.TRUE.equals(user.getDeleted());
  }
}
