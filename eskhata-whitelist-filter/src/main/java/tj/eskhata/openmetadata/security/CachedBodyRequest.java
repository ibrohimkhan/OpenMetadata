/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Holds the request body in memory so it can be read twice: once by the whitelist check and once
 * by the authentication handler behind it. A servlet input stream is single-use, so without this
 * the handler downstream would receive an empty body.
 */
final class CachedBodyRequest extends HttpServletRequestWrapper {
  private final byte[] body;

  CachedBodyRequest(final HttpServletRequest request) throws IOException {
    super(request);
    this.body = request.getInputStream().readAllBytes();
  }

  String bodyAsString() {
    return new String(body, StandardCharsets.UTF_8);
  }

  @Override
  public ServletInputStream getInputStream() {
    return new ReplayStream(new ByteArrayInputStream(body));
  }

  @Override
  public BufferedReader getReader() {
    return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
  }

  private static final class ReplayStream extends ServletInputStream {
    private final ByteArrayInputStream source;

    private ReplayStream(final ByteArrayInputStream source) {
      this.source = source;
    }

    @Override
    public boolean isFinished() {
      return source.available() == 0;
    }

    @Override
    public boolean isReady() {
      return true;
    }

    @Override
    public void setReadListener(final ReadListener readListener) {
      throw new UnsupportedOperationException("Asynchronous reads are not supported");
    }

    @Override
    public int read() {
      return source.read();
    }
  }
}
