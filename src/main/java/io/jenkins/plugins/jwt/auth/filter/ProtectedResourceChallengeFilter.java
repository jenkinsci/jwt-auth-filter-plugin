package io.jenkins.plugins.jwt.auth.filter;

import hudson.Extension;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import jenkins.util.HttpServletFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Extension(ordinal = 100)
public class ProtectedResourceChallengeFilter implements HttpServletFilter {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(ProtectedResourceChallengeFilter.class);

    @Override
    public boolean handle(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws IOException, ServletException {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (config == null || !config.isProtectedResourceMetadataEnabled()) {
            return false;
        }

        ProtectedResourceMetadata protectedResource =
                config.findProtectedResource(httpRequest.getRequestURI(), httpRequest.getContextPath());
        if (protectedResource == null) {
            return false;
        }

        String authHeader = httpRequest.getHeader("Authorization");
        boolean hasBearerToken = authHeader != null && authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (hasBearerToken) {
            // JwtBearerTokenFilter (ordinal 200) already ran. If the token was valid it set a
            // JwtBearerTokenAuthentication in the security context — pass through in that case only.
            if (auth instanceof JwtBearerTokenAuthentication && auth.isAuthenticated()) {
                return false;
            }
            // Token was present but expired / invalid — re-challenge so the MCP client can refresh.
            LOG.debug(
                    "Bearer token on protected resource {} is invalid or expired — re-challenging",
                    httpRequest.getRequestURI());
        } else if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            // Already authenticated by Jenkins (e.g. HTTP basic with username/API token or a session).
            // Invalid basic credentials are rejected by Jenkins before reaching this filter.
            return false;
        }

        String metadataUrl = config.getProtectedResourceMetadataUrl(protectedResource);
        String wwwAuthenticate = buildWwwAuthenticate(metadataUrl, hasBearerToken);
        if (wwwAuthenticate != null) {
            httpResponse.setHeader("WWW-Authenticate", wwwAuthenticate);
        }
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String body = hasBearerToken
                ? "{\"error\":\"invalid_token\",\"error_description\":\"The access token is expired or invalid\"}"
                : "{\"error\":\"unauthorized\",\"error_description\":\"Authentication required\"}";
        httpResponse.getWriter().write(body);
        httpResponse.getWriter().flush();
        LOG.debug(
                "Challenged request to protected resource {} with metadata URL {}",
                httpRequest.getRequestURI(),
                metadataUrl);
        return true;
    }

    private static String buildWwwAuthenticate(String metadataUrl, boolean invalidToken) {
        if (metadataUrl == null || metadataUrl.isBlank() || metadataUrl.contains("\r") || metadataUrl.contains("\n")) {
            return null;
        }
        String value = "Bearer resource_metadata=\"" + metadataUrl + "\"";
        if (invalidToken) {
            value += ", error=\"invalid_token\", error_description=\"The access token is expired or invalid\"";
        }
        return value;
    }
}
