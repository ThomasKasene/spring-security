package org.springframework.security.oauth2.client.dpop;

import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.dpop.DpopHttpHeaderNames;
import org.springframework.security.oauth2.core.dpop.DpopTokenErrorCodes;
import org.springframework.util.Assert;

import java.io.IOException;
import java.net.URI;

/**
 * An extension of {@link OAuth2ErrorResponseErrorHandler}, this error handler also adds
 * any Authorization Server-provided nonces to its {@link DpopNonceRegistry}.
 *
 * @author Thomas Kåsene
 */
public final class DpopOAuth2ErrorResponseErrorHandler extends OAuth2ErrorResponseErrorHandler {

	private final DpopNonceRegistry dpopNonceRegistry;

	public DpopOAuth2ErrorResponseErrorHandler(DpopNonceRegistry dpopNonceRegistry) {
		Assert.notNull(dpopNonceRegistry, "dpopNonceRegistry cannot be null");
		this.dpopNonceRegistry = dpopNonceRegistry;
	}

	@Override
	public void handleError(URI uri, HttpMethod method, ClientHttpResponse response) throws IOException {
		try {
			super.handleError(uri, method, response);
		} catch (OAuth2AuthorizationException exception) {
			String errorCode = exception.getError().getErrorCode();
			if (DpopTokenErrorCodes.USE_DPOP_NONCE.equals(errorCode) || DpopTokenErrorCodes.INVALID_DPOP_PROOF.equals(errorCode)) {
				String authorizationServerDpopNonce = response.getHeaders().getFirst(DpopHttpHeaderNames.DPOP_NONCE);
				dpopNonceRegistry.registerNonce(method, uri, authorizationServerDpopNonce);
			}
			throw exception;
		}
	}
}
