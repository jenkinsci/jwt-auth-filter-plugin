package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Regression test for the interaction between {@link JwtBearerTokenCrumbExclusion} and another
 * {@link CrumbExclusion} that serves the request itself (as the mcp-server {@code Endpoint} does for
 * the MCP streamable endpoint).
 *
 * <p>Before the fix, {@link JwtBearerTokenCrumbExclusion} returned {@code false} without forwarding
 * the filter chain when a Bearer token was present but invalid/expired. The CSRF crumb filter then
 * handed the request to the next, lower-priority {@link CrumbExclusion}, which served it as the
 * anonymous user — so the RFC 6750 401 challenge from {@link ProtectedResourceChallengeFilter} was
 * never issued. This test reproduces that scenario with a competing request-consuming exclusion.
 */
@WithJenkins
class JwtBearerTokenCrumbExclusionTest {

    @Test
    void invalidBearerTokenIsChallengedAndNotConsumedByCompetingCrumbExclusion(JenkinsRule jenkinsRule)
            throws Exception {
        configure(jenkinsRule);

        // A structurally invalid token: rejected without any JWKS network access.
        HttpResponse<String> response = post(jenkinsRule.getURL() + "mcp-test/mcp", "not-a-valid-jwt");

        assertEquals(
                401,
                response.statusCode(),
                "An invalid Bearer token on a protected resource must be challenged with 401, "
                        + "not consumed by a competing CrumbExclusion. Body was: " + response.body());
        assertTrue(
                response.body().contains("invalid_token"),
                "Challenge body should signal invalid_token; body was: " + response.body());
        assertFalse(
                response.body().contains(ConsumingCrumbExclusion.MARKER),
                "The competing CrumbExclusion must not have handled the request; body was: " + response.body());
    }

    @Test
    void missingBearerTokenOnProtectedResourceIsChallengedBeforeCompetingCrumbExclusion(JenkinsRule jenkinsRule)
            throws Exception {
        configure(jenkinsRule);

        HttpResponse<String> response = post(jenkinsRule.getURL() + "mcp-test/mcp", null);

        assertEquals(
                401,
                response.statusCode(),
                "A protected resource without a bearer token must be challenged, "
                        + "not consumed by a competing CrumbExclusion.");
        assertTrue(response.body().contains("\"error\":\"unauthorized\""), response.body());
        assertFalse(response.body().contains(ConsumingCrumbExclusion.MARKER), response.body());
        assertTrue(
                response.headers().firstValue("WWW-Authenticate").orElse("").contains("oauth-protected-resource"),
                "Challenge should advertise protected-resource metadata.");
    }

    /**
     * Regression test for the double build trigger bug.
     *
     * <p>When a UI POST (e.g. a build request) reaches a protected path without a Bearer token,
     * {@link JwtBearerTokenCrumbExclusion#process} must return {@code false} <em>without</em> driving
     * the filter chain, so Jenkins core {@code CrumbFilter} performs normal CSRF crumb validation and
     * processes the request exactly once. The previous code called {@code chain.doFilter()} on this
     * branch and then returned {@code false}, so the request was processed here and again by
     * {@code CrumbFilter} after crumb validation — triggering the build twice.
     */
    @Test
    void noBearerTokenMustNotDriveChain(JenkinsRule jenkinsRule) throws Exception {
        configure(jenkinsRule);
        JwtBearerTokenFilterConfiguration.getInstance().setProtectedResources(List.of());
        String basePath = jenkinsRule.getURL().getPath().replaceAll("/$", "");
        String protectedUri = basePath + "/mcp-test/mcp";

        AtomicInteger chainCalls = new AtomicInteger(0);
        HttpServletRequest request = fakeRequest(protectedUri, null, basePath);
        HttpServletResponse response = fakeResponse();
        FilterChain chain = (req, resp) -> chainCalls.incrementAndGet();

        boolean handled = new JwtBearerTokenCrumbExclusion().process(request, response, chain);

        assertFalse(
                handled,
                "A no-Bearer-token request on a protected path must return false so CrumbFilter runs "
                        + "normal CSRF crumb validation exactly once.");
        assertEquals(
                0,
                chainCalls.get(),
                "A no-Bearer-token request must NOT drive the filter chain here; doing so double-processes "
                        + "the UI request and triggers the build twice.");
    }

    @Test
    void noBearerTokenOnProtectedResourceMustDriveChain(JenkinsRule jenkinsRule) throws Exception {
        configure(jenkinsRule);
        String basePath = jenkinsRule.getURL().getPath().replaceAll("/$", "");
        String protectedUri = basePath + "/mcp-test/mcp";

        AtomicInteger chainCalls = new AtomicInteger(0);
        HttpServletRequest request = fakeRequest(protectedUri, null, basePath);
        HttpServletResponse response = fakeResponse();
        FilterChain chain = (req, resp) -> chainCalls.incrementAndGet();

        boolean handled = new JwtBearerTokenCrumbExclusion().process(request, response, chain);

        assertTrue(handled, "A protected resource without a bearer token must be handled for the OIDC challenge.");
        assertEquals(1, chainCalls.get(), "The protected-resource request must be passed down the chain once.");
    }

    private static HttpServletRequest fakeRequest(String requestURI, String authHeader, String contextPath) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                JwtBearerTokenCrumbExclusionTest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getRequestURI" -> requestURI;
                    case "getContextPath" -> contextPath;
                    case "getHeader" -> "Authorization".equalsIgnoreCase((String) args[0]) ? authHeader : null;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static HttpServletResponse fakeResponse() {
        return (HttpServletResponse) Proxy.newProxyInstance(
                JwtBearerTokenCrumbExclusionTest.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class},
                (proxy, method, args) -> defaultValue(method.getReturnType()));
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == long.class) {
            return 0L;
        }
        return null;
    }

    private void configure(JenkinsRule jenkinsRule) throws Exception {
        String basePath = jenkinsRule.getURL().getPath().replaceAll("/$", "");
        Issuer issuer = new Issuer("https://jwks.example.com/certs", "test-audience", basePath + "/mcp-test/**");

        ProtectedResourceMetadata protectedResource = new ProtectedResourceMetadata("/mcp-test/mcp");
        protectedResource.setAuthorizationServer("https://auth.example.com");
        protectedResource.setScopesSupportedValue("openid,profile");

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setIssuers(List.of(issuer));
        config.setProtectedResources(List.of(protectedResource));

        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        FullControlOnceLoggedInAuthorizationStrategy strategy = new FullControlOnceLoggedInAuthorizationStrategy();
        strategy.setAllowAnonymousRead(false);
        jenkinsRule.jenkins.setAuthorizationStrategy(strategy);
    }

    private HttpResponse<String> post(String url, String bearerToken) throws Exception {
        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"));
        if (bearerToken != null) {
            requestBuilder.header("Authorization", "Bearer " + bearerToken);
        }
        return httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Mimics the mcp-server {@code Endpoint}: a {@link CrumbExclusion} that serves the request itself
     * (returning HTTP 200) instead of forwarding the chain. Its default ordinal (0) is lower than the
     * pinned ordinal of {@link JwtBearerTokenCrumbExclusion}, so it must never get the chance to
     * handle a Bearer-bearing request to the protected endpoint.
     */
    @TestExtension
    public static class ConsumingCrumbExclusion extends CrumbExclusion {

        static final String MARKER = "consumed-as-anonymous";

        @Override
        public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            String uri = request.getRequestURI();
            if (uri != null && uri.contains("/mcp-test/")) {
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write("{\"status\":\"FAILED\",\"message\":\"" + MARKER + "\"}");
                response.getWriter().flush();
                return true;
            }
            return false;
        }
    }
}
