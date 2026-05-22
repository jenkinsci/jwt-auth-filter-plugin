package io.jenkins.plugins.jwt.auth.filter;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.util.HttpResponses;
import java.util.List;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.json.JsonHttpResponse;

@Extension
public class ProtectedResourceMetadataAction implements UnprotectedRootAction {

    private static final String WELL_KNOWN_ROOT = ".well-known";
    static final String WELL_KNOWN_PATH = ".well-known/oauth-protected-resource";

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return WELL_KNOWN_ROOT;
    }

    @SuppressWarnings({"lgtm[jenkins/csrf]", "lgtm[jenkins/no-permission-check]", "unused"})
    public HttpResponse doIndex() {
        return HttpResponses.notFound();
    }

    @SuppressWarnings({"lgtm[jenkins/csrf]", "lgtm[jenkins/no-permission-check]", "unused"})
    public HttpResponse doDynamic(StaplerRequest2 request) {
        return metadataResponseFor(extractProtectedResourcePath(request));
    }

    private String extractProtectedResourcePath(StaplerRequest2 request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isBlank() && requestUri.startsWith(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }
        String wellKnownPrefix = "/" + WELL_KNOWN_PATH;
        if (requestUri.equals(wellKnownPrefix) || requestUri.equals(wellKnownPrefix + "/")) {
            return "/";
        }
        if (requestUri.startsWith(wellKnownPrefix + "/")) {
            return requestUri.substring(wellKnownPrefix.length());
        }
        return null;
    }

    private HttpResponse metadataResponseFor(String wellKnownPath) {
        if (wellKnownPath == null) {
            return HttpResponses.notFound();
        }
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (config == null || !config.isProtectedResourceMetadataEnabled()) {
            return HttpResponses.notFound();
        }

        ProtectedResourceMetadata protectedResourceMetadata =
                config.getProtectedResourceMetadataForWellKnownPath(wellKnownPath);
        if (protectedResourceMetadata == null) {
            return HttpResponses.notFound();
        }

        String resource = config.getEffectiveResource(protectedResourceMetadata);
        if (resource == null || resource.isBlank()) {
            return HttpResponses.notFound();
        }

        String authorizationServer = protectedResourceMetadata.getAuthorizationServer();
        if (authorizationServer == null || authorizationServer.isBlank()) {
            return HttpResponses.notFound();
        }

        JSONObject metadata = new JSONObject();
        metadata.put("resource", resource);
        metadata.put("authorization_servers", List.of(authorizationServer.trim()));
        List<String> scopesSupported = protectedResourceMetadata.getScopesSupported();
        if (!scopesSupported.isEmpty()) {
            metadata.put("scopes_supported", scopesSupported);
        }
        return new JsonHttpResponse(metadata);
    }
}
