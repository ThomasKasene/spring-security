package org.springframework.security.oauth2.client.dpop;

import org.springframework.http.HttpMethod;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * A registry to tie an endpoint to a nonce provided by the server of that endpoint.
 *
 * @author Thomas Kåsene
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-8" target="_blank">RFC 9449
 * Section 8 Authorization Server-Provided Nonce</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-9" target="_blank">RFC 9449
 * Section 9 Resource Server-Provided Nonce</a>
 */
public abstract class DpopNonceRegistry {

	/**
	 * Register a nonce to be used when constructing a DPoP proof JWT to be sent to the specified
	 * {@code method} and {@code uri}. If a nonce is already registered for the given endpoint,
	 * it will be replaced by the new one.
	 * @param method the {@link HttpMethod} for which the {@code nonce} should be registered
	 * @param uri the {@link URI} for which the {@code nonce} should be registered
	 * @param nonce the nonce to register
	 */
	public final void registerNonce(HttpMethod method, URI uri, String nonce) {
		URI uriWithoutParamsAndFragments = stripQueryParametersAndFragments(uri);
		doRegisterNonce(method, uriWithoutParamsAndFragments.toString(), nonce);
	}

	/**
	 * Obtains the nonce to be used during construction of a DPoP proof JWT to be sent to the
	 * specified {@code method} and {@code uri}.
	 * @param method the {@link HttpMethod} to use in the nonce lookup
	 * @param uri the {@link URI} to use in the nonce lookup
	 * @return the registered nonce, or {@code null} if not found
	 */
	public final String getNonce(HttpMethod method, URI uri) {
		URI uriWithoutParamsAndFragments = stripQueryParametersAndFragments(uri);
		return doGetNonce(method, uriWithoutParamsAndFragments.toString());
	}

	protected abstract void doRegisterNonce(HttpMethod method, String uri, String nonce);

	protected abstract String doGetNonce(HttpMethod method, String uri);

	/**
	 * Strips away the query and fragment parts of the {@code uri}.
	 *
	 * @return a copy of {@code uri}, but without any query and fragment parts
	 */
	protected final URI stripQueryParametersAndFragments(URI uri) {
		try {
			return new URI(uri.getScheme(), uri.getRawUserInfo(), uri.getHost(), uri.getPort(),
					uri.getRawPath(), null, null);
		} catch (URISyntaxException exception) {
			throw new IllegalArgumentException(
					"Failed to strip away the query parameters and fragments from URI", exception);
		}
	}
}
