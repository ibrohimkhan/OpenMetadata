/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The list of principals allowed to log in, backed by a plain text file that operators edit by
 * hand on the server. One principal per line; blank lines and lines starting with '#' are ignored.
 *
 * <p>The file is re-read when its modification time changes, so edits take effect without a
 * restart. If it cannot be read the list becomes empty rather than stale: an unreadable file must
 * not silently turn the whitelist off.
 */
final class LoginWhitelist {
  private static final Logger LOG = LoggerFactory.getLogger(LoginWhitelist.class);

  private static final String COMMENT_PREFIX = "#";
  private static final String AT_SIGN = "@";
  private static final long RECHECK_INTERVAL_MILLIS = 10_000L;
  private static final long UNKNOWN_TIMESTAMP = -1L;
  private static final int MAX_LINES = 50_000;

  private final Path file;
  private final long recheckIntervalMillis;
  private final Object reloadLock = new Object();
  private volatile Set<String> entries = Set.of();
  private long loadedTimestamp = UNKNOWN_TIMESTAMP;
  private long lastCheckMillis = UNKNOWN_TIMESTAMP;

  LoginWhitelist(final Path file) {
    this(file, RECHECK_INTERVAL_MILLIS);
  }

  /** Visible for tests, which cannot wait out the production re-check window. */
  LoginWhitelist(final Path file, final long recheckIntervalMillis) {
    this.file = file;
    this.recheckIntervalMillis = recheckIntervalMillis;
  }

  boolean contains(final String principal) {
    refreshIfDue();
    return entries.contains(Principals.normalize(principal));
  }

  int size() {
    refreshIfDue();
    return entries.size();
  }

  private void refreshIfDue() {
    final long now = System.currentTimeMillis();
    synchronized (reloadLock) {
      if (now - lastCheckMillis >= recheckIntervalMillis) {
        lastCheckMillis = now;
        reloadIfModified();
      }
    }
  }

  private void reloadIfModified() {
    final long current = lastModifiedMillis();
    if (current != loadedTimestamp) {
      loadedTimestamp = current;
      entries = readEntries();
    }
  }

  private long lastModifiedMillis() {
    long timestamp = UNKNOWN_TIMESTAMP;
    try {
      timestamp = Files.getLastModifiedTime(file).toMillis();
    } catch (IOException e) {
      LOG.error(
          "Whitelist file '{}' is unreadable ({}). Logins outside OpenMetadata will be denied.",
          file,
          e.getMessage());
    }
    return timestamp;
  }

  private Set<String> readEntries() {
    Set<String> loaded = Set.of();
    try {
      loaded = parse(Files.readAllLines(file, StandardCharsets.UTF_8));
    } catch (IOException e) {
      LOG.error(
          "Whitelist file '{}' could not be read ({}). Treating the list as empty.",
          file,
          e.getMessage());
    }
    return loaded;
  }

  private Set<String> parse(final List<String> lines) {
    Set<String> parsed = Set.of();
    if (lines.size() > MAX_LINES) {
      LOG.error(
          "Whitelist file '{}' holds {} lines, above the {} line limit. Refusing to load it.",
          file,
          lines.size(),
          MAX_LINES);
    } else {
      parsed = collect(lines);
    }
    return parsed;
  }

  private Set<String> collect(final List<String> lines) {
    final Set<String> accepted = new HashSet<>();
    int skipped = 0;
    int malformed = 0;
    for (final String line : lines) {
      final String entry = Principals.normalize(line);
      if (isIgnorable(entry)) {
        skipped++;
      } else if (entry.contains(AT_SIGN)) {
        accepted.add(entry);
      } else {
        malformed++;
        LOG.warn("Whitelist entry '{}' ignored: it has no '{}'.", entry, AT_SIGN);
      }
    }
    logLoad(accepted.size(), skipped, malformed);
    return Set.copyOf(accepted);
  }

  private void logLoad(final int accepted, final int skipped, final int malformed) {
    LOG.info(
        "Whitelist loaded from '{}': {} entries, {} blank or comment lines, {} malformed.",
        file,
        accepted,
        skipped,
        malformed);
  }

  private static boolean isIgnorable(final String entry) {
    return entry.isEmpty() || entry.startsWith(COMMENT_PREFIX);
  }
}
