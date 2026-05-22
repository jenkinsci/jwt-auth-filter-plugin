package io.jenkins.plugins.jwt.auth.filter;

import hudson.Extension;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import jenkins.util.HttpServletFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Extension
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
        if (authHeader != null && authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX)) {
            return false;
        }

        String metadataUrl = config.getProtectedResourceMetadataUrl(protectedResource);
        if (metadataUrl != null
                && !metadataUrl.isBlank()
                && !metadataUrl.contains("\r")
                && !metadataUrl.contains("\n")) {
            httpResponse.setHeader("WWW-Authenticate", "Bearer resource_metadata=\"" + metadataUrl + "\"");
        }
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse
                .getWriter()
                .write("{\"error\":\"unauthorized\",\"error_description\":\"Authentication required\"}");
        httpResponse.getWriter().flush();
        LOG.debug(
                "Challenged request to protected resource {} with metadata URL {}",
                httpRequest.getRequestURI(),
                metadataUrl);
        return true;
    }
}
