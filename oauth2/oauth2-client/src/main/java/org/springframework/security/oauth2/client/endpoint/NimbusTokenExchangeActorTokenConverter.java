package org.springframework.security.oauth2.client.endpoint;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * A {@link Converter} that creates a {@link TokenExchangePartyIdentifierToken} containing an actor token
 * as a signed JSON Web Token (JWS), which can be used in an OAuth 2.0 Token Exchange request.
 * The private/secret key used for signing the JWS is supplied by the {@code com.nimbusds.jose.jwk.JWK} resolver
 * provided via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK.
 *
 * @author Thomas Kåsene
 * @since 6.1
 * @see Converter
 * @see com.nimbusds.jose.jwk.JWK
 * @see TokenExchangeActorTokenConverterRequest
 * @see TokenExchangePartyIdentifierToken
 * @see org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider#setActorTokenConverter(Converter)
 */
public final class NimbusTokenExchangeActorTokenConverter
		implements Converter<TokenExchangeActorTokenConverterRequest, TokenExchangePartyIdentifierToken> {

	private static final String INVALID_KEY_ERROR_CODE = "invalid_key"; // TODO: Which spec is this code from?

	private static final String INVALID_ALGORITHM_ERROR_CODE = "invalid_algorithm"; // TODO: Which spec is this code from?

	private final Function<ClientRegistration, JWK> jwkResolver;

	private final Map<String, JwsEncoderHolder> jwsEncoders = new ConcurrentHashMap<>();

	private Function<TokenExchangeActorTokenConverterRequest, JwtClaimsSet> jwtClaimsSetResolver =
			this::defaultJwtClaimsSetResolver;

	/**
	 * Constructs a {@code NimbusTokenExchangeActorTokenConverter} using the provided parameters.
	 * @param jwkResolver the resolver that provides the {@code com.nimbusds.jose.jwk.JWK}
	 * associated to the {@link ClientRegistration client}
	 */
	public NimbusTokenExchangeActorTokenConverter(Function<ClientRegistration, JWK> jwkResolver) {
		Assert.notNull(jwkResolver, "jwkResolver cannot be null");
		this.jwkResolver = jwkResolver;
	}

	@Override
	public TokenExchangePartyIdentifierToken convert(TokenExchangeActorTokenConverterRequest request) {
		Assert.notNull(request, "request cannot be null");

		ClientRegistration clientRegistration = request.getClientRegistration();

		JWK jwk = this.jwkResolver.apply(clientRegistration);
		if (jwk == null) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_KEY_ERROR_CODE,
					"Failed to resolve JWK signing key for client registration '"
							+ clientRegistration.getRegistrationId() + "'.",
					null);
			throw new OAuth2AuthorizationException(oauth2Error);
		}

		JwsAlgorithm jwsAlgorithm = resolveAlgorithm(jwk);
		if (jwsAlgorithm == null) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ALGORITHM_ERROR_CODE,
					"Unable to resolve JWS (signing) algorithm from JWK associated to client registration '"
							+ clientRegistration.getRegistrationId() + "'.",
					null);
			throw new OAuth2AuthorizationException(oauth2Error);
		}

		JwsEncoderHolder jwsEncoderHolder = this.jwsEncoders.compute(clientRegistration.getRegistrationId(),
				(clientRegistrationId, currentJwsEncoderHolder) -> {
					if (currentJwsEncoderHolder != null && currentJwsEncoderHolder.getJwk().equals(jwk)) {
						return currentJwsEncoderHolder;
					}
					JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
					return new JwsEncoderHolder(new NimbusJwtEncoder(jwkSource), jwk);
				});

		JwsHeader jwsHeader = JwsHeader.with(jwsAlgorithm).build();
		JwtClaimsSet jwtClaimsSet = jwtClaimsSetResolver.apply(request);

		JwtEncoder jwsEncoder = jwsEncoderHolder.getJwsEncoder();
		Jwt jws = jwsEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		return new TokenExchangePartyIdentifierToken(jws.getTokenValue(), "urn:ietf:params:oauth:token-type:jwt");
	}

	private JwtClaimsSet defaultJwtClaimsSetResolver(TokenExchangeActorTokenConverterRequest request) {
		return JwtClaimsSet.builder()
				.issuer(request.getClientRegistration().getClientId())
				.audience(List.of(request.getClientRegistration().getProviderDetails().getTokenUri()))
				.subject(request.getActingParty())
				.expiresAt(Instant.now().plusSeconds(60))
				.build();
	}

	private static JwsAlgorithm resolveAlgorithm(JWK jwk) {
		JwsAlgorithm jwsAlgorithm = null;

		if (jwk.getAlgorithm() != null) {
			jwsAlgorithm = SignatureAlgorithm.from(jwk.getAlgorithm().getName());
			if (jwsAlgorithm == null) {
				jwsAlgorithm = MacAlgorithm.from(jwk.getAlgorithm().getName());
			}
		}

		if (jwsAlgorithm == null) {
			if (KeyType.RSA.equals(jwk.getKeyType())) {
				jwsAlgorithm = SignatureAlgorithm.RS256;
			}
			else if (KeyType.EC.equals(jwk.getKeyType())) {
				jwsAlgorithm = SignatureAlgorithm.ES256;
			}
			else if (KeyType.OCT.equals(jwk.getKeyType())) {
				jwsAlgorithm = MacAlgorithm.HS256;
			}
		}

		return jwsAlgorithm;
	}

	private static final class JwsEncoderHolder {

		private final JwtEncoder jwsEncoder;

		private final JWK jwk;

		private JwsEncoderHolder(JwtEncoder jwsEncoder, JWK jwk) {
			this.jwsEncoder = jwsEncoder;
			this.jwk = jwk;
		}

		private JwtEncoder getJwsEncoder() {
			return this.jwsEncoder;
		}

		private JWK getJwk() {
			return this.jwk;
		}

	}

	/**
	 * Sets the function to be used when generating a {@link JwtClaimsSet} based on the
	 * {@link TokenExchangeActorTokenConverterRequest actor token converter request}.
	 *
	 * @param jwtClaimsSetResolver the {@link Function} used when generating a {@link JwtClaimsSet}
	 */
	public void setJwtClaimsSetResolver(
			Function<TokenExchangeActorTokenConverterRequest, JwtClaimsSet> jwtClaimsSetResolver) {
		Assert.notNull(jwtClaimsSetResolver, "jwtClaimsSetResolver cannot be null");
		this.jwtClaimsSetResolver = jwtClaimsSetResolver;
	}
}
