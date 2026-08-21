/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import java.util.Locale;

/**
 * Normalisation shared by the whitelist file and the access decision. Both sides have to agree
 * on case and whitespace, otherwise a hand-edited file silently stops matching.
 */
final class Principals {
  private static final String BYTE_ORDER_MARK = "﻿";
  private static final String EMPTY = "";
  private static final char AT_SIGN = '@';

  private Principals() {}

  static String normalize(final String value) {
    String normalized = EMPTY;
    if (value != null) {
      normalized = value.replace(BYTE_ORDER_MARK, EMPTY).trim().toLowerCase(Locale.ROOT);
    }
    return normalized;
  }

  /**
   * OpenMetadata derives a username from the part before '@' and lowercases it, which is also how
   * adminPrincipals entries are written.
   */
  static String localPart(final String principal) {
    final String normalized = normalize(principal);
    final int separator = normalized.indexOf(AT_SIGN);
    return separator > 0 ? normalized.substring(0, separator) : normalized;
  }
}
