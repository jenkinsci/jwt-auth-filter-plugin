package io.jenkins.plugins.jwt.auth.filter;

import com.nimbusds.jwt.SignedJWT;
import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A JWT bearer token that exclude requested from Crumb that contains a valid signed JWT token.
 *
 * <p>Pinned to a higher-than-default ordinal so it runs before other {@link CrumbExclusion}s that may
 * consume the request themselves (notably the mcp-server {@code Endpoint}). Otherwise a competing
 * exclusion could handle a request carrying an invalid/expired Bearer token as anonymous, bypassing
 * the RFC 6750 401 challenge issued by {@link ProtectedResourceChallengeFilter}.
 */
@Extension(ordinal = 100)
public class JwtBearerTokenCrumbExclusion extends CrumbExclusion {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(JwtBearerTokenCrumbExclusion.class);

    @Override
    public boolean process(HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain chain)
            throws IOException, ServletException {

        // Skip if not on configured path
        String requestURI = httpRequest.getRequestURI();
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (!config.anyMatch(requestURI)) {
            LOG.trace(
                    "Request URI '{}' does not match any protected paths - skipping JWT Bearer Crumb filter",
                    requestURI);
            return false;
        }

        // No Bearer token: return false so CrumbFilter runs normal CSRF validation exactly once.
        // Metadata-backed resources must continue through the chain to issue an OIDC challenge.
        String authHeader = httpRequest.getHeader("Authorization");
        boolean hasBearerToken = authHeader != null && authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX);
        if (!hasBearerToken) {
            if (config.isProtectedResource(requestURI, httpRequest.getContextPath())) {
                LOG.trace(
                        "Request URI '{}' is a protected resource without a bearer token; driving chain for OIDC challenge",
                        requestURI);
                chain.doFilter(httpRequest, httpResponse);
                return true;
            }
            return false;
        }

        // A Bearer token is present on a protected path.
        String tokenString = authHeader.substring(JwtBearerTokenFilter.BEARER_PREFIX.length());
        try {
            SignedJWT signedJWT = SignedJWT.parse(tokenString);

            // Get all issuers that match the request path
            for (Issuer issuer : config.getIssuers()) {
                if (issuer.matchesPath(requestURI)) {
                    if (JwtBearerTokenFilter.verifyJwtSignature(signedJWT, issuer)) {
                        LOG.info(
                                "Valid JWT token found in request for issuer {}, excluding from Crumb",
                                issuer.getJwksUrl());
                        httpRequest.setAttribute(JwtBearerTokenCrumbExclusion.class.getName(), Boolean.TRUE);
                        chain.doFilter(httpRequest, httpResponse);
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse or verify JWT token from Authorization header", e);
        }

        // Bearer token present but invalid/expired: still drive the chain ourselves so the request
        // reaches the HttpServletFilter phase (and the ProtectedResourceChallengeFilter 401 challenge)
        // instead of being consumed by a lower-priority CrumbExclusion (e.g. the mcp-server Endpoint)
        // that would serve it as anonymous and bypass the RFC 6750 challenge.
        chain.doFilter(httpRequest, httpResponse);
        return true;
    }
}
