/*
 *  Copyright 2026 Eskhata Bank
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package tj.eskhata.openmetadata.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openmetadata.service.security.AuthServeletHandler;

class GuardedAuthServletHandlerTest {
  private static final long RELOAD_EVERY_TIME = 0L;
  private static final String LISTED = "ivanov@eskhata.tj";
  private static final String UNLISTED = "sidorov@eskhata.tj";
  private static final String PASSWORD_FIELD = "\",\"password\":\"c2VjcmV0\"}";

  @TempDir Path directory;

  @Test
  void passesListedPrincipalToTheWrappedHandler() throws IOException {
    final RecordingHandler wrapped = new RecordingHandler();
    final HttpServletResponse response = mock(HttpServletResponse.class);

    handler(wrapped).handleLogin(loginRequest(LISTED), response);

    assertTrue(wrapped.called);
  }

  @Test
  void rejectsUnlistedPrincipalWithoutReachingTheHandler() throws IOException {
    final RecordingHandler wrapped = new RecordingHandler();
    final StringWriter body = new StringWriter();
    final HttpServletResponse response = responseWriting(body);

    handler(wrapped).handleLogin(loginRequest(UNLISTED), response);

    assertTrue(!wrapped.called);
    assertTrue(body.toString().contains("\"code\":403"));
    assertTrue(body.toString().contains("Access denied"));
  }

  @Test
  void answersInRussianWhenTheBrowserAsksForIt() throws IOException {
    final StringWriter body = new StringWriter();
    final HttpServletResponse response = responseWriting(body);
    final HttpServletRequest request = loginRequest(UNLISTED);
    when(request.getHeader("Accept-Language")).thenReturn("ru-RU,ru;q=0.9,en;q=0.8");

    handler(new RecordingHandler()).handleLogin(request, response);

    assertTrue(body.toString().contains("Доступ запрещён"));
  }

  @Test
  void leavesTheBodyReadableForTheHandlerBehindIt() throws IOException {
    final RecordingHandler wrapped = new RecordingHandler();

    handler(wrapped).handleLogin(loginRequest(LISTED), mock(HttpServletResponse.class));

    assertNotNull(wrapped.seenBody);
    assertTrue(wrapped.seenBody.contains(LISTED), "handler saw: " + wrapped.seenBody);
    assertTrue(wrapped.seenBody.contains("password"), "handler saw: " + wrapped.seenBody);
  }

  @Test
  void doesNotInspectNonPostLogins() throws IOException {
    final RecordingHandler wrapped = new RecordingHandler();
    final HttpServletRequest request = loginRequest(UNLISTED);
    when(request.getMethod()).thenReturn("GET");

    handler(wrapped).handleLogin(request, mock(HttpServletResponse.class));

    assertTrue(wrapped.called);
  }

  @Test
  void rejectsAMalformedBody() throws IOException {
    final RecordingHandler wrapped = new RecordingHandler();
    final StringWriter body = new StringWriter();

    handler(wrapped).handleLogin(requestWithBody("not json at all"), responseWriting(body));

    assertTrue(!wrapped.called);
    assertTrue(body.toString().contains("\"code\":403"));
  }

  @Test
  void delegatesEverythingOtherThanLogin() {
    final RecordingHandler wrapped = new RecordingHandler();
    final GuardedAuthServletHandler guard = handlerOf(wrapped);
    final HttpServletRequest request = mock(HttpServletRequest.class);
    final HttpServletResponse response = mock(HttpServletResponse.class);

    guard.handleLogout(request, response);
    guard.handleCallback(request, response);
    guard.handleRefresh(request, response);

    assertEquals(3, wrapped.otherCalls);
    assertEquals(wrapped, guard.delegate());
  }

  private GuardedAuthServletHandler handler(final AuthServeletHandler wrapped) throws IOException {
    final Path file = directory.resolve("list.txt");
    Files.writeString(file, LISTED + "\n", StandardCharsets.UTF_8);
    return new GuardedAuthServletHandler(
        wrapped,
        new LoginPolicy(
            new LoginWhitelist(file, RELOAD_EVERY_TIME), Set.of(), principal -> null));
  }

  private GuardedAuthServletHandler handlerOf(final AuthServeletHandler wrapped) {
    return new GuardedAuthServletHandler(
        wrapped,
        new LoginPolicy(
            new LoginWhitelist(directory.resolve("absent.txt"), RELOAD_EVERY_TIME),
            Set.of(),
            principal -> null));
  }

  private static HttpServletRequest loginRequest(final String principal) throws IOException {
    return requestWithBody("{\"email\":\"" + principal + PASSWORD_FIELD);
  }

  private static HttpServletRequest requestWithBody(final String body) throws IOException {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getMethod()).thenReturn("POST");
    when(request.getInputStream()).thenReturn(streamOf(body));
    when(request.getHeader(anyString())).thenReturn(null);
    return request;
  }

  private static HttpServletResponse responseWriting(final StringWriter target) throws IOException {
    final HttpServletResponse response = mock(HttpServletResponse.class);
    when(response.getWriter()).thenReturn(new PrintWriter(target, true));
    return response;
  }

  private static ServletInputStream streamOf(final String body) {
    final ByteArrayInputStream source =
        new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
    return new ServletInputStream() {
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
        throw new UnsupportedOperationException();
      }

      @Override
      public int read() {
        return source.read();
      }
    };
  }

  /** Records what the wrapped handler received, which is what the guard must not disturb. */
  private static final class RecordingHandler implements AuthServeletHandler {
    private boolean called;
    private String seenBody;
    private int otherCalls;

    @Override
    public void handleLogin(final HttpServletRequest req, final HttpServletResponse resp) {
      called = true;
      try {
        seenBody = new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      } catch (IOException e) {
        seenBody = null;
      }
    }

    @Override
    public void handleLogout(final HttpServletRequest req, final HttpServletResponse resp) {
      otherCalls++;
    }

    @Override
    public void handleCallback(final HttpServletRequest req, final HttpServletResponse resp) {
      otherCalls++;
    }

    @Override
    public void handleRefresh(final HttpServletRequest req, final HttpServletResponse resp) {
      otherCalls++;
    }
  }
}
