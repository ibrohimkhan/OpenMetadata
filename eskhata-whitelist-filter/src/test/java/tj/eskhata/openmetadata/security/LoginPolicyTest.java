/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openmetadata.schema.entity.teams.User;

class LoginPolicyTest {
  private static final long RELOAD_EVERY_TIME = 0L;
  private static final String LISTED = "ivanov@eskhata.tj";
  private static final String UNLISTED = "sidorov@eskhata.tj";
  private static final String ADMIN = "kholmatov.i@eskhata.com";

  @TempDir Path directory;

  @Test
  void allowsPrincipalOnTheList() throws IOException {
    assertEquals(LoginDecision.ALLOWED, policy(noUsers()).decide(LISTED));
  }

  @Test
  void deniesPrincipalNeitherListedNorKnown() throws IOException {
    assertEquals(LoginDecision.DENIED_NOT_LISTED, policy(noUsers()).decide(UNLISTED));
  }

  @Test
  void allowsExistingOpenMetadataUserEvenWhenUnlisted() throws IOException {
    final Function<String, User> users = usersOf(UNLISTED, activeUser());

    assertEquals(LoginDecision.ALLOWED, policy(users).decide(UNLISTED));
  }

  @Test
  void deniesUserDeletedInOpenMetadataEvenWhenListed() throws IOException {
    final Function<String, User> users = usersOf(LISTED, deletedUser());

    assertEquals(LoginDecision.DENIED_DELETED_IN_OM, policy(users).decide(LISTED));
  }

  @Test
  void deniesDeletedUserAheadOfTheAdminException() throws IOException {
    final Function<String, User> users = usersOf(ADMIN, deletedUser());

    assertEquals(LoginDecision.DENIED_DELETED_IN_OM, policy(users).decide(ADMIN));
  }

  @Test
  void allowsAdminPrincipalMissingFromTheList() throws IOException {
    assertEquals(LoginDecision.ALLOWED, policy(noUsers()).decide(ADMIN));
  }

  @Test
  void allowsAdminPrincipalWhenTheListFileIsGone() {
    final LoginPolicy policy =
        new LoginPolicy(
            new LoginWhitelist(directory.resolve("absent.txt"), RELOAD_EVERY_TIME),
            Set.of("kholmatov.i"),
            noUsers());

    assertEquals(LoginDecision.ALLOWED, policy.decide(ADMIN));
    assertEquals(LoginDecision.DENIED_NOT_LISTED, policy.decide(LISTED));
  }

  @Test
  void matchesRegardlessOfCase() throws IOException {
    assertEquals(LoginDecision.ALLOWED, policy(noUsers()).decide("IVANOV@ESKHATA.TJ"));
  }

  @Test
  void deniesRequestWithoutPrincipal() throws IOException {
    assertEquals(LoginDecision.DENIED_UNREADABLE_REQUEST, policy(noUsers()).decide(null));
    assertEquals(LoginDecision.DENIED_UNREADABLE_REQUEST, policy(noUsers()).decide("   "));
  }

  private LoginPolicy policy(final Function<String, User> users) throws IOException {
    final Path file = directory.resolve("list.txt");
    Files.writeString(file, LISTED + "\n", StandardCharsets.UTF_8);
    return new LoginPolicy(
        new LoginWhitelist(file, RELOAD_EVERY_TIME), Set.of("kholmatov.i"), users);
  }

  private static Function<String, User> noUsers() {
    return principal -> null;
  }

  private static Function<String, User> usersOf(final String principal, final User user) {
    final Map<String, User> known = Map.of(principal, user);
    return known::get;
  }

  private static User activeUser() {
    return new User().withName("someone").withDeleted(false);
  }

  private static User deletedUser() {
    return new User().withName("someone").withDeleted(true);
  }
}
