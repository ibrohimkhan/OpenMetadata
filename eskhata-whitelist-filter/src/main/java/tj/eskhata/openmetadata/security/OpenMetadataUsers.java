/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import java.util.function.Function;
import org.openmetadata.schema.entity.teams.User;
import org.openmetadata.service.Entity;
import org.openmetadata.service.exception.EntityNotFoundException;
import org.openmetadata.service.util.EntityUtil.Fields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Looks a principal up among OpenMetadata users by e-mail, returning null when there is none.
 *
 * <p>Kept behind a Function so the access rules can be tested without standing up entity
 * repositories. Note that OpenMetadata's own query ignores the deleted flag, so soft-deleted users
 * are returned here and {@link LoginPolicy} is the one that rejects them.
 */
final class OpenMetadataUsers implements Function<String, User> {
  private static final Logger LOG = LoggerFactory.getLogger(OpenMetadataUsers.class);

  @Override
  public User apply(final String principal) {
    User user = null;
    try {
      user = Entity.getUserRepository().getByEmail(null, principal, Fields.EMPTY_FIELDS);
    } catch (EntityNotFoundException e) {
      LOG.debug("No OpenMetadata user has e-mail '{}'.", principal);
    }
    return user;
  }
}
