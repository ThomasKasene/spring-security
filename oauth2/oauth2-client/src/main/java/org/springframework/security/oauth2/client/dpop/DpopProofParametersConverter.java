package org.springframework.security.oauth2.client.dpop;

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
import org.springframework.security.oauth2.core.dpop.DpopProofJwtClaimNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

// TODO: Javadoc
public class DpopProofParametersConverter implements Converter<DpopProofParameters, String> {

	private static final String DPOP_JWT_MEDIA_TYPE = "dpop+jwt";

	private static final String INVALID_KEY_ERROR_CODE = "invalid_key";

	private static final String INVALID_ALGORITHM_ERROR_CODE = "invalid_algorithm";

	private final Function<ClientRegistration, JWK> jwkResolver;

	private final Base64.Encoder urlEncoder;

	private final Map<String, JwsEncoderHolder> jwsEncoders;

	public DpopProofParametersConverter(Function<ClientRegistration, JWK> jwkResolver) {
		Assert.notNull(jwkResolver, "jwkResolver cannot be null");
		this.jwkResolver = jwkResolver;
		this.urlEncoder = Base64.getUrlEncoder().withoutPadding();
		this.jwsEncoders = new ConcurrentHashMap<>();
	}

	@Override
	public String convert(DpopProofParameters dpopProofParameters) {

		ClientRegistration clientRegistration = dpopProofParameters.getClientRegistration();
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

		// @formatter:off
        JwsHeader.Builder headersBuilder = JwsHeader.with(jwsAlgorithm)
                .type(DPOP_JWT_MEDIA_TYPE)
                .jwk(jwk.toPublicJWK().toJSONObject());
        // @formatter:on

		Instant issuedAt = Instant.now();
		String uriAsString = stripQueryParametersAndFragments(dpopProofParameters.getUri()).toString();

		// @formatter:off
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .id(UUID.randomUUID().toString())
                .issuedAt(issuedAt)
                .claim(DpopProofJwtClaimNames.HTM, dpopProofParameters.getHttpMethod().name())
                .claim(DpopProofJwtClaimNames.HTU, uriAsString);
        // @formatter:on

		String accessTokenValue = dpopProofParameters.getAccessTokenValue();
		if (accessTokenValue != null) {
			String accessTokenValueHash = generateHashFrom(accessTokenValue);
			claimsBuilder.claim(DpopProofJwtClaimNames.ATH, accessTokenValueHash);
		}

		String nonce = dpopProofParameters.getNonce();
		if (nonce != null) {
			claimsBuilder.claim(DpopProofJwtClaimNames.NONCE, nonce);
		}

		JwsHeader jwsHeader = headersBuilder.build();
		JwtClaimsSet jwtClaimsSet = claimsBuilder.build();

		JwsEncoderHolder jwsEncoderHolder = this.jwsEncoders.compute(clientRegistration.getRegistrationId(),
				(clientRegistrationId, currentJwsEncoderHolder) -> {
					if (currentJwsEncoderHolder != null && currentJwsEncoderHolder.jwk().equals(jwk)) {
						return currentJwsEncoderHolder;
					}
					JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
					return new JwsEncoderHolder(new NimbusJwtEncoder(jwkSource), jwk);
				});

		JwtEncoder jwsEncoder = jwsEncoderHolder.jwsEncoder();
		Jwt jws = jwsEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));
		return jws.getTokenValue();
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
			} else if (KeyType.EC.equals(jwk.getKeyType())) {
				jwsAlgorithm = SignatureAlgorithm.ES256;
			} else if (KeyType.OCT.equals(jwk.getKeyType())) {
				jwsAlgorithm = MacAlgorithm.HS256;
			}
		}

		return jwsAlgorithm;
	}

	private static URI stripQueryParametersAndFragments(URI uri) {
		try {
			return new URI(uri.getScheme(), uri.getRawUserInfo(), uri.getHost(), uri.getPort(),
					uri.getRawPath(), null, null);
		} catch (URISyntaxException exception) {
			throw new IllegalArgumentException(
					"Failed to strip away the query parameters and fragments from URI", exception);
		}
	}

	private String generateHashFrom(String tokenValue) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			byte[] digest = messageDigest.digest(tokenValue.getBytes(StandardCharsets.UTF_8));
			return this.urlEncoder.encodeToString(digest);
		} catch (NoSuchAlgorithmException exception) {
			throw new RuntimeException(exception);
		}
	}

	private record JwsEncoderHolder(JwtEncoder jwsEncoder, JWK jwk) {
	}
}
