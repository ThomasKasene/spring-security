package org.springframework.security.oauth2.client.dpop;

import org.springframework.http.HttpMethod;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory implementation of {@link DpopNonceRegistry}.
 *
 * @author Thomas Kåsene
 */
public final class InMemoryDpopNonceRegistry extends DpopNonceRegistry {

	private final Map<MethodAndUri, String> nonceByMethodAndUri = new ConcurrentHashMap<>();

	@Override
	protected String doGetNonce(HttpMethod method, String uri) {
		return nonceByMethodAndUri.get(new MethodAndUri(method, uri));
	}

	@Override
	protected void doRegisterNonce(HttpMethod method, String uri, String nonce) {
		MethodAndUri methodAndUri = new MethodAndUri(method, uri);
		nonceByMethodAndUri.put(methodAndUri, nonce);
	}

	private record MethodAndUri(HttpMethod method, String uri) {
	}
}
