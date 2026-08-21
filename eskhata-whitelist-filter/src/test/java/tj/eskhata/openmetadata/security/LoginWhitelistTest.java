/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LoginWhitelistTest {
  private static final long RELOAD_EVERY_TIME = 0L;

  @TempDir Path directory;

  @Test
  void acceptsListedPrincipal() throws IOException {
    final LoginWhitelist whitelist = whitelistOf("ivanov@eskhata.tj", "petrov@eskhata.com");

    assertTrue(whitelist.contains("ivanov@eskhata.tj"));
    assertTrue(whitelist.contains("petrov@eskhata.com"));
    assertFalse(whitelist.contains("sidorov@eskhata.tj"));
  }

  @Test
  void ignoresCaseAndSurroundingWhitespace() throws IOException {
    final LoginWhitelist whitelist = whitelistOf("  Ivanov@Eskhata.TJ  ");

    assertTrue(whitelist.contains("ivanov@eskhata.tj"));
    assertTrue(whitelist.contains("IVANOV@ESKHATA.TJ"));
  }

  @Test
  void skipsCommentsAndBlankLines() throws IOException {
    final LoginWhitelist whitelist =
        whitelistOf("# IT department", "", "   ", "ivanov@eskhata.tj", "# petrov@eskhata.com");

    assertEquals(1, whitelist.size());
    assertFalse(whitelist.contains("petrov@eskhata.com"));
  }

  @Test
  void skipsLinesWithoutAtSign() throws IOException {
    final LoginWhitelist whitelist = whitelistOf("ivanov", "ivanov@eskhata.tj");

    assertEquals(1, whitelist.size());
    assertFalse(whitelist.contains("ivanov"));
  }

  @Test
  void toleratesByteOrderMarkFromEditors() throws IOException {
    final LoginWhitelist whitelist = whitelistOf("﻿ivanov@eskhata.tj");

    assertTrue(whitelist.contains("ivanov@eskhata.tj"));
  }

  @Test
  void deniesEverythingWhenFileIsMissing() {
    final LoginWhitelist whitelist =
        new LoginWhitelist(directory.resolve("absent.txt"), RELOAD_EVERY_TIME);

    assertEquals(0, whitelist.size());
    assertFalse(whitelist.contains("ivanov@eskhata.tj"));
  }

  @Test
  void picksUpEditsWithoutRestart() throws IOException {
    final Path file = directory.resolve("list.txt");
    Files.writeString(file, "ivanov@eskhata.tj\n", StandardCharsets.UTF_8);
    final LoginWhitelist whitelist = new LoginWhitelist(file, RELOAD_EVERY_TIME);
    assertFalse(whitelist.contains("petrov@eskhata.com"));

    Files.writeString(file, "ivanov@eskhata.tj\npetrov@eskhata.com\n", StandardCharsets.UTF_8);
    touch(file);

    assertTrue(whitelist.contains("petrov@eskhata.com"));
    assertTrue(whitelist.contains("ivanov@eskhata.tj"));
  }

  @Test
  void emptiesTheListWhenTheFileDisappears() throws IOException {
    final Path file = directory.resolve("list.txt");
    Files.writeString(file, "ivanov@eskhata.tj\n", StandardCharsets.UTF_8);
    final LoginWhitelist whitelist = new LoginWhitelist(file, RELOAD_EVERY_TIME);
    assertTrue(whitelist.contains("ivanov@eskhata.tj"));

    Files.delete(file);

    assertFalse(whitelist.contains("ivanov@eskhata.tj"));
    assertEquals(0, whitelist.size());
  }

  @Test
  void treatsAnEmptiedFileAsAnEmptyList() throws IOException {
    final Path file = directory.resolve("list.txt");
    Files.writeString(file, "ivanov@eskhata.tj\n", StandardCharsets.UTF_8);
    final LoginWhitelist whitelist = new LoginWhitelist(file, RELOAD_EVERY_TIME);
    assertTrue(whitelist.contains("ivanov@eskhata.tj"));

    Files.writeString(file, "", StandardCharsets.UTF_8);
    touch(file);

    assertFalse(whitelist.contains("ivanov@eskhata.tj"));
  }

  private LoginWhitelist whitelistOf(final String... lines) throws IOException {
    final Path file = directory.resolve("list.txt");
    Files.write(file, List.of(lines), StandardCharsets.UTF_8);
    return new LoginWhitelist(file, RELOAD_EVERY_TIME);
  }

  /** Reload is keyed on modification time, which can be identical for two quick writes. */
  private static void touch(final Path file) throws IOException {
    Files.setLastModifiedTime(
        file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 60_000L));
  }
}
