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
 * Text shown to a rejected user. OpenMetadata renders whatever the login endpoint puts in the
 * JSON "message" field, so localisation has to happen here rather than in the UI bundles.
 *
 * <p>Every denial reason maps to the same wording on purpose: telling an anonymous caller whether
 * an account exists, is merely unlisted, or was deleted would leak account state.
 */
final class DenialMessages {
  private static final String RUSSIAN_PREFIX = "ru";

  private static final String RUSSIAN_TEXT =
      "Доступ запрещён: ваша учётная запись не включена в список доступа. "
          + "Обратитесь к администратору.";

  private static final String ENGLISH_TEXT =
      "Access denied: your account is not on the access list. Contact your administrator.";

  private DenialMessages() {}

  static String forAcceptLanguage(final String acceptLanguage) {
    return prefersRussian(acceptLanguage) ? RUSSIAN_TEXT : ENGLISH_TEXT;
  }

  private static boolean prefersRussian(final String acceptLanguage) {
    return acceptLanguage != null
        && acceptLanguage.toLowerCase(Locale.ROOT).trim().startsWith(RUSSIAN_PREFIX);
  }
}
