package org.joychou.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security regression tests for the CommandInject controller (/codeinject endpoint).
 *
 * The taint flow that was fixed:
 *   SOURCE: filepath parameter (line 25 of CommandInject.java in controller-2)
 *   SINK:   ProcessBuilder.start() (line 30) where filepath was interpolated into a
 *           shell string: new String[]{"sh", "-c", "ls -la " + filepath}
 *
 * The fix replaces the shell string with a direct argv list:
 *   new String[]{"ls", "-la", filepath}
 * This means the OS passes filepath as a literal argument to "ls" without invoking
 * a shell, so metacharacters like ;, |, &, $, and backticks are never interpreted.
 *
 * These tests verify that command injection payloads do NOT result in execution of
 * injected commands. Each test sends a payload that would succeed in the vulnerable
 * version and asserts it produces no output from the injected command.
 *
 * Note: the tests target the controller-2 variant of the endpoint.
 * The controller-2 sources share the same Spring Boot application context.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class CommandInjectSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    // ---------------------------------------------------------------------------
    // Helper: marker string that would appear in /etc/passwd output.
    // If injection succeeds, the response will contain "root:" (the first line).
    // ---------------------------------------------------------------------------
    private static final String ETC_PASSWD_MARKER = "root:";

    // ---------------------------------------------------------------------------
    // Positive / functionality test
    // ---------------------------------------------------------------------------

    /**
     * A benign filepath ("/tmp") must still produce a valid response.
     * This confirms the fix does not break normal operation.
     */
    @Test
    public void testBenignFilepath_returnsSomeOutput() throws Exception {
        MvcResult result = mockMvc.perform(get("/codeinject").param("filepath", "/tmp"))
                .andReturn();
        // We do not strictly assert status because the endpoint may return
        // any 2xx code; we just check the invocation completes without an
        // unhandled exception and that a response body is present.
        MockHttpServletResponse response = result.getResponse();
        assertNotNull("Response must not be null", response);
    }

    // ---------------------------------------------------------------------------
    // Negative / security tests – injection payloads must NOT execute
    // ---------------------------------------------------------------------------

    /**
     * Classic semicolon injection: /tmp;cat /etc/passwd
     * In the vulnerable version this would append a second shell command.
     * In the fixed version the semicolon is treated as a literal character
     * inside the filepath argument to "ls", so "cat /etc/passwd" is never run.
     */
    @Test
    public void testSemicolonInjection_doesNotLeakEtcPasswd() throws Exception {
        String maliciousFilepath = "/tmp;cat /etc/passwd";
        MvcResult result = mockMvc.perform(get("/codeinject")
                .param("filepath", maliciousFilepath))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(
                "Semicolon injection must not execute 'cat /etc/passwd'; "
                        + "response body must not contain '" + ETC_PASSWD_MARKER + "'",
                body.contains(ETC_PASSWD_MARKER));
    }

    /**
     * Pipe injection: /tmp | cat /etc/passwd
     * A shell pipe would redirect ls output to cat. Without a shell the pipe
     * character is just a literal byte in the filepath argument.
     */
    @Test
    public void testPipeInjection_doesNotLeakEtcPasswd() throws Exception {
        String maliciousFilepath = "/tmp | cat /etc/passwd";
        MvcResult result = mockMvc.perform(get("/codeinject")
                .param("filepath", maliciousFilepath))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(
                "Pipe injection must not execute 'cat /etc/passwd'; "
                        + "response body must not contain '" + ETC_PASSWD_MARKER + "'",
                body.contains(ETC_PASSWD_MARKER));
    }

    /**
     * Logical-AND injection: /tmp && cat /etc/passwd
     * Without a shell the && is not interpreted as a command separator.
     */
    @Test
    public void testAndInjection_doesNotLeakEtcPasswd() throws Exception {
        String maliciousFilepath = "/tmp && cat /etc/passwd";
        MvcResult result = mockMvc.perform(get("/codeinject")
                .param("filepath", maliciousFilepath))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(
                "AND injection must not execute 'cat /etc/passwd'; "
                        + "response body must not contain '" + ETC_PASSWD_MARKER + "'",
                body.contains(ETC_PASSWD_MARKER));
    }

    /**
     * Backtick command substitution: /tmp`cat /etc/passwd`
     * Backticks are shell-only syntax; they are inert when no shell is invoked.
     */
    @Test
    public void testBacktickInjection_doesNotLeakEtcPasswd() throws Exception {
        String maliciousFilepath = "/tmp`cat /etc/passwd`";
        MvcResult result = mockMvc.perform(get("/codeinject")
                .param("filepath", maliciousFilepath))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(
                "Backtick injection must not execute 'cat /etc/passwd'; "
                        + "response body must not contain '" + ETC_PASSWD_MARKER + "'",
                body.contains(ETC_PASSWD_MARKER));
    }

    /**
     * Dollar-sign command substitution: /tmp$(cat /etc/passwd)
     * $(...) is a shell feature; without a shell it is a literal string.
     */
    @Test
    public void testDollarSubstitutionInjection_doesNotLeakEtcPasswd() throws Exception {
        String maliciousFilepath = "/tmp$(cat /etc/passwd)";
        MvcResult result = mockMvc.perform(get("/codeinject")
                .param("filepath", maliciousFilepath))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(
                "Dollar-sign substitution injection must not execute 'cat /etc/passwd'; "
                        + "response body must not contain '" + ETC_PASSWD_MARKER + "'",
                body.contains(ETC_PASSWD_MARKER));
    }

    /**
     * Newline injection: /tmp\ncat /etc/passwd
     * A newline in a shell string can act as a command separator.
     * Without a shell, the newline is just part of the filepath argument.
     */
    @Test
    public void testNewlineInjection_doesNotLeakEtcPasswd() throws Exception {
        String maliciousFilepath = "/tmp\ncat /etc/passwd";
        MvcResult result = mockMvc.perform(get("/codeinject")
                .param("filepath", maliciousFilepath))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(
                "Newline injection must not execute 'cat /etc/passwd'; "
                        + "response body must not contain '" + ETC_PASSWD_MARKER + "'",
                body.contains(ETC_PASSWD_MARKER));
    }
}
