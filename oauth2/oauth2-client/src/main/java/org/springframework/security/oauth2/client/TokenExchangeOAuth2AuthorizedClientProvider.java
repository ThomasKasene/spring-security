package org.springframework.security.oauth2.client;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeActorTokenConverterRequest;
import org.springframework.security.oauth2.client.endpoint.DefaultTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.TokenExchangePartyIdentifierToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

/*
1. Considering that the acting party can appear in several token exchanges (for example, an admin or
   a support user), and the fact that a principal may choose to delegate access to multiple such actors,
   is it even possible to manage all those `OAuth2AuthorizedClient`s with the current APIs
   (`OAuth2AuthorizedClientRepository`, etc)?
2. Is it acceptable to add a new constant, `org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.N_A`,
   to represent the value registered as part of RFC8693?
   Reference: https://www.rfc-editor.org/rfc/rfc8693#name-oauth-access-token-type-reg
*/


/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider} for the
 * {@link AuthorizationGrantType#TOKEN_EXCHANGE urn:ietf:params:oauth:grant-type:token-exchange} grant.
 *
 * @author Thomas Kåsene
 * @since 6.1
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultTokenExchangeTokenResponseClient
 */
public class TokenExchangeOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

	private static final String AUDIENCE_ATTR_NAME = OAuth2AuthorizationContext.class.getName().concat(".AUDIENCE");
	private static final String RESOURCE_ATTR_NAME = OAuth2AuthorizationContext.class.getName().concat(".RESOURCE");
	private static final String DELEGATION_ATTR_NAME = OAuth2AuthorizationContext.class.getName().concat(".DELEGATION");
	private static final String DELEGATION_ACTING_PARTY_ATTR_NAME = OAuth2AuthorizationContext.class.getName()
			.concat(".DELEGATION_ACTING_PARTY");
	private static final String REQUESTED_TOKEN_TYPE_ATTR_NAME = OAuth2AuthorizationContext.class.getName()
			.concat(".REQUESTED_TOKEN_TYPE");

    private OAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient =
            new DefaultTokenExchangeTokenResponseClient();

	private Function<OAuth2AuthorizationContext, TokenExchangePartyIdentifierToken> subjectTokenResolver =
			this::resolveFromJwt;

	private Converter<TokenExchangeActorTokenConverterRequest, TokenExchangePartyIdentifierToken> actorTokenConverter;

    private Duration clockSkew = Duration.ofSeconds(60);

    private Clock clock = Clock.systemUTC();

    // TODO: Javadoc
    @Override
    @Nullable
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
        Assert.notNull(context, "context cannot be null");
        ClientRegistration clientRegistration = context.getClientRegistration();
        if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(clientRegistration.getAuthorizationGrantType())) {
            return null;
        }
        OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
        if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
            // If client is already authorized but access token is NOT expired then no
            // need for re-authorization
            return null;
        }
		TokenExchangePartyIdentifierToken subjectToken = subjectTokenResolver.apply(context);
		if (subjectToken == null) {
			return null;
		}
		TokenExchangePartyIdentifierToken actorToken = null;
		Boolean shouldDelegateToActingParty =
				Objects.requireNonNullElse(context.getAttribute(DELEGATION_ATTR_NAME), false);
		if (shouldDelegateToActingParty) {
			Assert.notNull(this.actorTokenConverter, "actorTokenConverter cannot be null");
			String actingParty = Objects.requireNonNullElse(context.getAttribute(DELEGATION_ACTING_PARTY_ATTR_NAME),
					clientRegistration.getClientId());
			TokenExchangeActorTokenConverterRequest actorTokenConverterRequest =
					new TokenExchangeActorTokenConverterRequest(clientRegistration, actingParty);
			actorToken = this.actorTokenConverter.convert(actorTokenConverterRequest);
		}
		String audience = context.getAttribute(AUDIENCE_ATTR_NAME);
		URI resource = context.getAttribute(RESOURCE_ATTR_NAME);
		String requestedTokenType = context.getAttribute(REQUESTED_TOKEN_TYPE_ATTR_NAME);
        TokenExchangeGrantRequest tokenExchangeGrantRequest = new TokenExchangeGrantRequest(
                clientRegistration, subjectToken, actorToken, audience, resource, requestedTokenType);
        OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, tokenExchangeGrantRequest);
		// TODO: Is this correct, considering pt 1 at the top of this file?
        return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
                tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
    }

    private TokenExchangePartyIdentifierToken resolveFromJwt(OAuth2AuthorizationContext context) {
		if (!(context.getPrincipal().getPrincipal() instanceof Jwt jwt)) {
			return null;
		}
		return new TokenExchangePartyIdentifierToken(jwt.getTokenValue(), "urn:ietf:params:oauth:token-type:jwt");
    }

    private OAuth2AccessTokenResponse getTokenResponse(
			ClientRegistration clientRegistration, TokenExchangeGrantRequest tokenExchangeGrantRequest) {
        try {
            return this.accessTokenResponseClient.getTokenResponse(tokenExchangeGrantRequest);
        } catch (OAuth2AuthorizationException exception) {
            throw new ClientAuthorizationException(
					exception.getError(), clientRegistration.getRegistrationId(), exception);
        }
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    /**
     * Sets the client used when requesting an access token credential at the Token
     * Endpoint for the {@code urn:ietf:params:oauth:grant-type:token-exchange} grant.
     * @param accessTokenResponseClient the client used when requesting an access token
     * credential at the Token Endpoint for the {@code urn:ietf:params:oauth:grant-type:token-exchange} grant
     */
    public void setAccessTokenResponseClient(
            OAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient) {
        Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    /**
     * Sets the maximum acceptable clock skew, which is used when checking the
     * {@link OAuth2AuthorizedClient#getAccessToken() access token} expiry. The default is
     * 60 seconds.
     *
     * <p>
     * An access token is considered expired if
     * {@code OAuth2AccessToken#getExpiresAt() - clockSkew} is before the current time
     * {@code clock#instant()}.
     * @param clockSkew the maximum acceptable clock skew
     */
    public void setClockSkew(Duration clockSkew) {
        Assert.notNull(clockSkew, "clockSkew cannot be null");
        Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
        this.clockSkew = clockSkew;
    }

    /**
     * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the access
     * token expiry.
     * @param clock the clock
     */
    public void setClock(Clock clock) {
        Assert.notNull(clock, "clock cannot be null");
        this.clock = clock;
    }

	/**
	 * Sets the {@link Function} to use when resolving the subject token.
	 * @param subjectTokenResolver the resolver
	 */
	public void setSubjectTokenResolver(
			Function<OAuth2AuthorizationContext, TokenExchangePartyIdentifierToken> subjectTokenResolver) {
		Assert.notNull(subjectTokenResolver, "subjectTokenResolver cannot be null");
		this.subjectTokenResolver = subjectTokenResolver;
	}

	/**
	 * Sets the {@link Converter} to use when generating an {@link TokenExchangePartyIdentifierToken actor token}
	 * based on a {@link TokenExchangeActorTokenConverterRequest}.
	 * @param actorTokenConverter the converter
	 */
	public void setActorTokenConverter(
			Converter<TokenExchangeActorTokenConverterRequest, TokenExchangePartyIdentifierToken> actorTokenConverter) {
		this.actorTokenConverter = actorTokenConverter;
	}

	// TODO: Javadoc
	public static Consumer<Map<String, Object>> delegateTo(String actingParty) {
		Assert.hasText(actingParty, "actingParty is required");
		return attributes -> {
			attributes.put(DELEGATION_ATTR_NAME, true);
			attributes.put(DELEGATION_ACTING_PARTY_ATTR_NAME, actingParty);
		};
	}

	// TODO: Javadoc
	public static Consumer<Map<String, Object>> delegateToClient() {
		return attributes -> attributes.put(DELEGATION_ATTR_NAME, true);
	}

	// TODO: Javadoc
	public static Consumer<Map<String, Object>> audience(String audience) {
		return attributes -> attributes.put(AUDIENCE_ATTR_NAME, audience);
	}

	// TODO: Should it accept a URI or a String (or overload it, for both)?
	// TODO: Javadoc
	public static Consumer<Map<String, Object>> resource(URI audience) {
		// TODO: Should we do validation here? And if so, should we also do it in setDefaultResource? And what about
		//  in the TokenExchangeGrantBuilder?
		if (audience != null && !(audience.isAbsolute() || audience.getRawFragment() != null)) {
			// TODO: Throw some kind of exception, probably, but which one?
		}
		return (attributes) -> attributes.put(RESOURCE_ATTR_NAME, audience);
	}

	// TODO: Javadoc
	public static Consumer<Map<String, Object>> requestedTokenType(String requestedTokenType) {
		return (attributes) -> attributes.put(REQUESTED_TOKEN_TYPE_ATTR_NAME, requestedTokenType);
	}

}
