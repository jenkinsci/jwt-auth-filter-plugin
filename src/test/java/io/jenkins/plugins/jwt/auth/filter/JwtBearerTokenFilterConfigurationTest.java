package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import jenkins.model.JenkinsLocationConfiguration;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Tests for JWT Bearer Token Filter Configuration roundtrip functionality.
 */
@WithJenkins
class JwtBearerTokenFilterConfigurationTest {

    @Test
    void shouldAnyMatch(JenkinsRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();

        // Create test issuers
        Issuer issuer1 = new Issuer("https://example1.com", "audience1", "/api/**");
        Issuer issuer2 = new Issuer("https://example2.com", "audience2", "/**/test/**");
        config.setIssuers(Arrays.asList(issuer1, issuer2));

        // Test path matching
        assertTrue(config.anyMatch("/api/test"), "/api/test should match first issuer");
        assertTrue(config.anyMatch("/foo/test/bar"), "/foo/test/bar should match second issuer");
        assertFalse(config.anyMatch("/other/path"), "/other/path should not match any issuer");
    }

    @Test
    void testGetMatchingIssuer(JenkinsRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();

        // Create test issuers
        Issuer issuer1 = new Issuer("https://example1.com", "audience1", "/api/**");
        Issuer issuer2 = new Issuer("https://example2.com", "audience2", "/**/test/**");
        config.setIssuers(Arrays.asList(issuer1, issuer2));

        // Test getting matching issuer
        Issuer matching = config.getMatchingIssuer("/api/something");
        assertNotNull(matching, "Should find matching issuer for /api/something");
        assertEquals("https://example1.com", matching.getJwksUrl());

        matching = config.getMatchingIssuer("/foo/test/bar");
        assertNotNull(matching, "Should find matching issuer for /foo/test/bar");
        assertEquals("https://example2.com", matching.getJwksUrl());

        matching = config.getMatchingIssuer("/other/path");
        assertNull(matching, "Should not find matching issuer for /other/path");
    }

    @Test
    void configRoundtrip(JenkinsRule jenkinsRule) throws Exception {

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        assertNotNull(config, "Configuration instance should not be null");

        // Create test issuers
        Issuer issuer1 = new Issuer(
                "https://keycloak.example.com/realms/test/protocol/openid-connect/certs", "test-jenkins", "/**/api/**");
        issuer1.setUsernameClaim("sub");
        issuer1.setNameClaim("full_name");
        issuer1.setEmailClaim("mail");
        issuer1.setGroupsClaim("roles");

        Issuer issuer2 = new Issuer(
                "https://keycloak2.example.com/realms/test/protocol/openid-connect/certs", "test-jenkins2", "/mcp/**");
        List<Issuer> testIssuers = Arrays.asList(issuer1, issuer2);

        // Set values and save
        config.setIssuers(testIssuers);
        config.save();

        // Round trip
        jenkinsRule.configRoundtrip();

        // Then - Verify values are set
        List<Issuer> savedIssuers = config.getIssuers();
        assertNotNull(savedIssuers, "Issuers should not be null");
        assertEquals(2, savedIssuers.size(), "Should have 2 issuers");

        Issuer savedIssuer1 = savedIssuers.get(0);
        assertEquals(
                "https://keycloak.example.com/realms/test/protocol/openid-connect/certs", savedIssuer1.getJwksUrl());
        assertEquals("test-jenkins", savedIssuer1.getAllowedAudience());
        assertEquals("/**/api/**", savedIssuer1.getProtectedPaths());
        assertEquals("sub", savedIssuer1.getUsernameClaim());
        assertEquals("full_name", savedIssuer1.getNameClaim());
        assertEquals("mail", savedIssuer1.getEmailClaim());
        assertEquals("roles", savedIssuer1.getGroupsClaim());

        Issuer savedIssuer2 = savedIssuers.get(1);
        assertEquals(
                "https://keycloak2.example.com/realms/test/protocol/openid-connect/certs", savedIssuer2.getJwksUrl());
        assertEquals("test-jenkins2", savedIssuer2.getAllowedAudience());
        assertEquals("/mcp/**", savedIssuer2.getProtectedPaths());
    }

    @Test
    void shouldMatchProtectedResourcesWithExactPathOnly(JenkinsRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setProtectedResources(List.of(
                protectedResource("/mcp", "https://auth.example.com"),
                protectedResource("/me", "https://auth2.example.com")));

        assertTrue(config.isProtectedResource("/jenkins/mcp", "/jenkins"));
        assertTrue(config.isProtectedResource("/jenkins/me", "/jenkins"));
        assertFalse(config.isProtectedResource("/jenkins/mcp/child", "/jenkins"));
        assertFalse(config.isProtectedResource("/jenkins/api/json", "/jenkins"));
    }

    @Test
    void shouldResolveProtectedResourceMetadataByPath(JenkinsRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setProtectedResources(List.of(
                protectedResource("/mcp", "https://auth.example.com"),
                protectedResource("/me", "https://auth2.example.com")));

        ProtectedResourceMetadata mcp = config.findProtectedResource("/jenkins/mcp", "/jenkins");
        assertNotNull(mcp);
        assertEquals("https://auth.example.com", mcp.getAuthorizationServer());

        ProtectedResourceMetadata mcpMetadata = config.getProtectedResourceMetadataForWellKnownPath("/mcp");
        assertNotNull(mcpMetadata);
        assertEquals("/mcp", mcpMetadata.getPath());

        assertNull(config.getProtectedResourceMetadataForWellKnownPath("/mcp/child"));
    }

    @Test
    void shouldBuildMetadataUrlsPerProtectedResource(JenkinsRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        ProtectedResourceMetadata protectedResource = protectedResource("/mcp", "https://auth.example.com");
        config.setProtectedResources(List.of(protectedResource));
        JenkinsLocationConfiguration.get().setUrl("https://jenkins.example.com/jenkins/");

        assertEquals(
                "https://jenkins.example.com/jenkins/.well-known/oauth-protected-resource/mcp",
                config.getProtectedResourceMetadataUrl(protectedResource));
        assertEquals("https://jenkins.example.com/jenkins/mcp", config.getEffectiveResource(protectedResource));
    }

    @Test
    void shouldSplitScopesSupportedCommaSeparatedValue() {
        ProtectedResourceMetadata protectedResourceMetadata = new ProtectedResourceMetadata("/mcp");
        protectedResourceMetadata.setScopesSupportedValue("openid, profile,email,roles,offline_access");

        assertEquals(
                List.of("openid", "profile", "email", "roles", "offline_access"),
                protectedResourceMetadata.getScopesSupported());
    }

    @Test
    void shouldLoadConfigureSecurityPageWithProtectedResources(JenkinsRule jenkinsRule) throws Exception {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setProtectedResources(List.of(protectedResource("/mcp", "https://auth.example.com")));
        config.save();

        assertEquals(
                200,
                jenkinsRule
                        .createWebClient()
                        .goTo("configureSecurity")
                        .getWebResponse()
                        .getStatusCode());
    }

    private static ProtectedResourceMetadata protectedResource(String path, String authorizationServer) {
        ProtectedResourceMetadata protectedResourceMetadata = new ProtectedResourceMetadata(path);
        protectedResourceMetadata.setAuthorizationServer(authorizationServer);
        return protectedResourceMetadata;
    }
}
