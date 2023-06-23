package org.springframework.security.oauth2.client.endpoint;

import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * An implementation of an {@link AbstractOAuth2AuthorizationGrantRequestEntityConverter} that converts the provided
 * {@link TokenExchangeGrantRequest} to a {@link RequestEntity} representation of an OAuth 2.0 Access Token Request for
 * the Token Exchange Grant.
 *
 * @author Thomas Kåsene
 * @since 6.1
 * @see AbstractOAuth2AuthorizationGrantRequestEntityConverter
 * @see TokenExchangeGrantRequest
 * @see RequestEntity
 */
public class TokenExchangeGrantRequestEntityConverter
		extends AbstractOAuth2AuthorizationGrantRequestEntityConverter<TokenExchangeGrantRequest> {

	@Override
	MultiValueMap<String, String> createParameters(TokenExchangeGrantRequest authorizationGrantRequest) {
		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, authorizationGrantRequest.getGrantType().getValue());
		parameters.add(OAuth2ParameterNames.SUBJECT_TOKEN, authorizationGrantRequest.getSubjectToken().getTokenValue());
		parameters.add(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, authorizationGrantRequest.getSubjectToken().getTokenType());
		if (authorizationGrantRequest.getActorToken() != null) {
			parameters.add(OAuth2ParameterNames.ACTOR_TOKEN, authorizationGrantRequest.getActorToken().getTokenValue());
			parameters.add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, authorizationGrantRequest.getActorToken().getTokenType());
		}
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			parameters.add(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		if (authorizationGrantRequest.getAudience() != null) {
			parameters.add(OAuth2ParameterNames.AUDIENCE, authorizationGrantRequest.getAudience());
		}
		if (authorizationGrantRequest.getResource() != null) {
			// TODO: Should this encoding be happening when the attribute is being set, way earlier, to avoid
			//  making "everyone" do the same thing?
			String resource = authorizationGrantRequest.getResource().toString();
			String uriEncodedResource = URLEncoder.encode(resource, StandardCharsets.UTF_8);
			parameters.add(OAuth2ParameterNames.RESOURCE, uriEncodedResource);
		}
		if (authorizationGrantRequest.getRequestedTokenType() != null) {
			parameters.add(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, authorizationGrantRequest.getRequestedTokenType());
		}
		if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		return parameters;
	}

}
