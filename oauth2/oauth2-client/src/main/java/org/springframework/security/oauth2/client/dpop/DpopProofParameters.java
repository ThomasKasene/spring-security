package org.springframework.security.oauth2.client.dpop;

import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

import java.net.URI;

// TODO: Rename, maybe
// TODO: Javadoc
public class DpopProofParameters {

	private final ClientRegistration clientRegistration;

	private final HttpMethod httpMethod;

	private final URI uri;

	private final String nonce;

	private final String accessTokenValue;

	public DpopProofParameters(ClientRegistration clientRegistration, HttpMethod httpMethod, URI uri, String nonce) {
		this(clientRegistration, httpMethod, uri, nonce, null);
	}

	public DpopProofParameters(ClientRegistration clientRegistration, HttpMethod httpMethod, URI uri, String nonce, String accessTokenValue) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(httpMethod, "httpMethod cannot be null");
		Assert.notNull(uri, "uri cannot be null");
		this.clientRegistration = clientRegistration;
		this.httpMethod = httpMethod;
		this.uri = uri;
		this.nonce = nonce;
		this.accessTokenValue = accessTokenValue;
	}

	public final ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	public final HttpMethod getHttpMethod() {
		return this.httpMethod;
	}

	public final URI getUri() {
		return this.uri;
	}

	public final String getNonce() {
		return this.nonce;
	}

	public final String getAccessTokenValue() {
		return this.accessTokenValue;
	}
}
