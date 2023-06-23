package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

// TODO: Javadoc
// TODO: Validation
public class TokenExchangeActorTokenConverterRequest {

	private final ClientRegistration clientRegistration;
	private final String actingParty;

	public TokenExchangeActorTokenConverterRequest(ClientRegistration clientRegistration, String actingParty) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(actingParty, "actingParty cannot be null");
		this.actingParty = actingParty;
		this.clientRegistration = clientRegistration;
	}

	public String getActingParty() {
		return actingParty;
	}

	public ClientRegistration getClientRegistration() {
		return clientRegistration;
	}
}
