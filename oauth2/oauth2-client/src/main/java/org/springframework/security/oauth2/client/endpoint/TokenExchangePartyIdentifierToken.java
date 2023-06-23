package org.springframework.security.oauth2.client.endpoint;

import org.springframework.util.Assert;

// TODO: Javadoc
// TODO: Rename
public final class TokenExchangePartyIdentifierToken {

	private final String tokenValue;
	private final String tokenType;

	public TokenExchangePartyIdentifierToken(String tokenValue, String tokenType) {
		Assert.notNull(tokenValue, "tokenValue cannot be null");
		Assert.notNull(tokenType, "tokenType cannot be null");
		this.tokenValue = tokenValue;
		this.tokenType = tokenType;
	}

	public String getTokenValue() {
		return tokenValue;
	}

	public String getTokenType() {
		return tokenType;
	}

}
