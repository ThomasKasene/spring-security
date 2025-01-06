package org.springframework.security.oauth2.client.dpop;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.dpop.DpopHttpHeaderNames;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link Converter} used to convert an {@link AbstractOAuth2AuthorizationGrantRequest}
 * to a {@link HttpHeaders} containing a DPoP proof JWT for a OAuth 2.0 Access Token
 * Request for the specific Authorization Grant.
 *
 * @author Thomas Kåsene
 */
public final class DpopTokenRequestHeadersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
        implements Converter<T, HttpHeaders> {

    private final DpopNonceRegistry dpopNonceRegistry;

    private final DpopProofParametersConverter dpopProofParametersConverter;

    private final Map<String, URI> tokenUrisByClientRegistrationId;

    public DpopTokenRequestHeadersConverter(DpopNonceRegistry dpopNonceRegistry, DpopProofParametersConverter dpopProofParametersConverter) {
        Assert.notNull(dpopNonceRegistry, "dpopNonceRegistry cannot be null");
        Assert.notNull(dpopProofParametersConverter, "dpopProofParametersConverter cannot be null");
        this.dpopNonceRegistry = dpopNonceRegistry;
        this.dpopProofParametersConverter = dpopProofParametersConverter;
        this.tokenUrisByClientRegistrationId = new HashMap<>();
    }

    @Override
    public HttpHeaders convert(T authorizationGrantRequest) {
        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
        URI tokenUri = this.tokenUrisByClientRegistrationId.computeIfAbsent(clientRegistration.getRegistrationId(),
                registrationId -> URI.create(clientRegistration.getProviderDetails().getTokenUri()));
        String authorizationServerNonce = this.dpopNonceRegistry.getNonce(HttpMethod.POST, tokenUri);
		DpopProofParameters dpopProofParameters = new DpopProofParameters(clientRegistration, HttpMethod.POST,
				tokenUri, authorizationServerNonce);
		String dpopProofValue = this.dpopProofParametersConverter.convert(dpopProofParameters);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(DpopHttpHeaderNames.DPOP, dpopProofValue);
        return httpHeaders;
    }
}
