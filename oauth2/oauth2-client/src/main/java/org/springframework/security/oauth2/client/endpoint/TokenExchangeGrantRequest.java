package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.net.URI;

/**
 * An OAuth 2.0 Token Exchange Grant request that holds a subject token and an optional actor token, identifying the
 * parties involved.
 *
 * @author Thomas Kåsene
 * @since 6.1
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc8693#name-request">Section 2.1 Token Exchange
 * Request</a>
 */
public class TokenExchangeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final TokenExchangePartyIdentifierToken subjectToken;

	private final TokenExchangePartyIdentifierToken actorToken;

	private final String audience;

	private final URI resource;

	private final String requestedTokenType;

	/**
	 * Constructs a {@code TokenExchangeGrantRequest} using the provided parameters.
	 * @param clientRegistration the client registration
	 * @param subjectToken the subject token
	 * @param actorToken the actor token
	 * @param audience the target audience
	 * @param resource the the target resource
	 * @param requestedTokenType the requested token type
	 */
    public TokenExchangeGrantRequest(ClientRegistration clientRegistration,
			TokenExchangePartyIdentifierToken subjectToken, TokenExchangePartyIdentifierToken actorToken,
			String audience, URI resource, String requestedTokenType) {
        super(AuthorizationGrantType.TOKEN_EXCHANGE, clientRegistration);
        Assert.isTrue(AuthorizationGrantType.TOKEN_EXCHANGE.equals(
                clientRegistration.getAuthorizationGrantType()),
                "clientRegistration.authorizationGrantType must be AuthorizationGrantType.TOKEN_EXCHANGE");
		Assert.notNull(subjectToken, "subjectToken cannot be null");
		this.subjectToken = subjectToken;
		this.actorToken = actorToken;
		this.audience = audience;
		this.resource = resource;
		this.requestedTokenType = requestedTokenType;
    }

	/**
	 * Returns the {@link TokenExchangePartyIdentifierToken subject token}.
	 * @return the subject token
	 */
	public TokenExchangePartyIdentifierToken getSubjectToken() {
		return this.subjectToken;
	}

	/**
	 * Returns the {@link TokenExchangePartyIdentifierToken actor token}.
	 * @return the actor token
	 */
	public TokenExchangePartyIdentifierToken getActorToken() {
		return this.actorToken;
	}

	/**
	 * Returns the intended audience of the token resulting from this token exchange.
	 * @return the audience
	 */
	public String getAudience() {
		return this.audience;
	}

	/**
	 * Returns the resource where the token resulting from this token exchange is intended to be used.
	 * @return the resource
	 */
	public URI getResource() {
		return this.resource;
	}

	/**
	 * Returns the type of token to request from this token exchange.
	 * @return the token type identifier for the token being requested
	 */
	public String getRequestedTokenType() {
		return this.requestedTokenType;
	}

}
