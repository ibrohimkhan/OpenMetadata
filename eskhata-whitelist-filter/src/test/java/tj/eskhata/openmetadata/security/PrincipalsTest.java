/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PrincipalsTest {

  @Test
  void normalisesCaseAndWhitespace() {
    assertEquals("ivanov@eskhata.tj", Principals.normalize("  Ivanov@Eskhata.TJ \n"));
  }

  @Test
  void treatsNullAsEmpty() {
    assertEquals("", Principals.normalize(null));
  }

  @Test
  void takesThePartBeforeTheAtSign() {
    assertEquals("kholmatov.i", Principals.localPart("Kholmatov.I@eskhata.com"));
  }

  @Test
  void keepsAValueThatHasNoAtSign() {
    assertEquals("admin", Principals.localPart("admin"));
  }

  @Test
  void answersInRussianOnlyForRussianPreference() {
    assertEquals(
        DenialMessages.forAcceptLanguage("en-GB,en;q=0.9"), DenialMessages.forAcceptLanguage(null));
    assertEquals(
        DenialMessages.forAcceptLanguage("ru-RU,ru;q=0.9"), DenialMessages.forAcceptLanguage("RU"));
  }
}
