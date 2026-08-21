/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

/** Outcome of the whitelist check, kept separate from the message shown to the user. */
enum LoginDecision {
  ALLOWED,
  DENIED_NOT_LISTED,
  DENIED_DELETED_IN_OM,
  DENIED_UNREADABLE_REQUEST;

  boolean isAllowed() {
    return this == ALLOWED;
  }
}
