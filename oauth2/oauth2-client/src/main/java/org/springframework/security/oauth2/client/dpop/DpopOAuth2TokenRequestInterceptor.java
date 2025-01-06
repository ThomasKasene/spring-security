package org.springframework.security.oauth2.client.dpop;

import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.dpop.DpopHttpHeaderNames;
import org.springframework.security.oauth2.core.dpop.DpopTokenErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.util.Assert;

import java.io.IOException;

public class DpopOAuth2TokenRequestInterceptor implements ClientHttpRequestInterceptor {

	private final DpopNonceRegistry dpopNonceRegistry;
	private final DpopProofParametersConverter dpopProofParametersConverter;

	private final HttpMessageConverter<OAuth2Error> oauth2ErrorConverter = new OAuth2ErrorHttpMessageConverter();

	public DpopOAuth2TokenRequestInterceptor(DpopNonceRegistry dpopNonceRegistry, DpopProofParametersConverter dpopProofParametersConverter) {
		Assert.notNull(dpopNonceRegistry, "dpopNonceRegistry cannot be null");
		Assert.notNull(dpopProofParametersConverter, "dpopProofParametersConverter cannot be null");
		this.dpopNonceRegistry = dpopNonceRegistry;
		this.dpopProofParametersConverter = dpopProofParametersConverter;
	}

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
		ClientHttpResponse response = execution.execute(request, body);
		if (HttpStatus.BAD_REQUEST.equals(response.getStatusCode())) {
			OAuth2Error oauth2Error = this.oauth2ErrorConverter.read(OAuth2Error.class, response);
			String errorCode = oauth2Error.getErrorCode();
			if (DpopTokenErrorCodes.USE_DPOP_NONCE.equals(errorCode) || DpopTokenErrorCodes.INVALID_DPOP_PROOF.equals(errorCode)) {
				String dpopNonce = response.getHeaders().getFirst(DpopHttpHeaderNames.DPOP_NONCE);
				if (dpopNonce != null) {
					this.dpopNonceRegistry.registerNonce(request.getMethod(), request.getURI(), dpopNonce);
//					DpopProofParameters dpopProofParameters = new DpopProofParameters(, request.getMethod(), request.getURI(), dpopNonce);
//					this.dpopProofParametersConverter.convert(dpopProofParameters);
					request.getHeaders().set(DpopHttpHeaderNames.DPOP, dpopNonce);
					response = execution.execute(request, body);
					// FIXME: AAAAH this won't work cause we need to generate new JWTs in this case ......
					//  or... do we? We need to regenerate the DPoP proof, but maybe we'll just use the same
					//  Authorization token..... but then again, we need a new way to resolve the ClientRegistration..
				}
			}
		}
		return response;
	}
}
