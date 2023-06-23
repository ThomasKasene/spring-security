package org.springframework.security.oauth2.client.endpoint;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

/**
 * The default implementation of an {@link OAuth2AccessTokenResponseClient} for the
 * {@link AuthorizationGrantType#TOKEN_EXCHANGE token-exchange} grant. This implementation uses a
 * {@link RestOperations} when requesting an access token credential at the Authorization
 * Server's Token Endpoint.
 *
 * @author Thomas Kåsene
 * @since 6.1
 * @see OAuth2AccessTokenResponseClient
 * @see TokenExchangeGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc8693#name-request">Section 2.1 Token Exchange Request</a>
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc8693#name-response">Section 2.2 Token Exchange Response</a>
 */
public class DefaultTokenExchangeTokenResponseClient
        implements OAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> {

    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

    private Converter<TokenExchangeGrantRequest, RequestEntity<?>> requestEntityConverter =
            new TokenExchangeGrantRequestEntityConverter();

    private RestOperations restOperations;

    public DefaultTokenExchangeTokenResponseClient() {
        RestTemplate restTemplate = new RestTemplate(
                Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(TokenExchangeGrantRequest tokenExchangeGrantRequest) {
        Assert.notNull(tokenExchangeGrantRequest, "tokenExchangeGrantRequest cannot be null");
        RequestEntity<?> request = this.requestEntityConverter.convert(tokenExchangeGrantRequest);
        ResponseEntity<OAuth2AccessTokenResponse> response = getResponse(request);
        // TODO: Snatch comment from the other OAuth2AccessTokenResponseClient implementations?
        return response.getBody(); // TODO: Is this all?
    }

    private ResponseEntity<OAuth2AccessTokenResponse> getResponse(RequestEntity<?> request) {
        try {
            return this.restOperations.exchange(request, OAuth2AccessTokenResponse.class);
        }
        catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
                            + ex.getMessage(),
                    null);
            throw new OAuth2AuthorizationException(oauth2Error, ex);
        }
    }

    /**
     * Sets the {@link Converter} used for converting the
     * {@link TokenExchangeGrantRequest} to a {@link RequestEntity}
     * representation of the OAuth 2.0 Access Token Request.
     * @param requestEntityConverter the {@link Converter} used for converting to a
     * {@link RequestEntity} representation of the Access Token Request
     */
    public void setRequestEntityConverter(
            Converter<TokenExchangeGrantRequest, RequestEntity<?>> requestEntityConverter) {
        Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
        this.requestEntityConverter = requestEntityConverter;
    }

    /**
     * Sets the {@link RestOperations} used when requesting the OAuth 2.0 Access Token
     * Response.
     *
     * <p>
     * <b>NOTE:</b> At a minimum, the supplied {@code restOperations} must be configured
     * with the following:
     * <ol>
     * <li>{@link HttpMessageConverter}'s - {@link FormHttpMessageConverter} and
     * {@link OAuth2AccessTokenResponseHttpMessageConverter}</li>
     * <li>{@link ResponseErrorHandler} - {@link OAuth2ErrorResponseErrorHandler}</li>
     * </ol>
     * @param restOperations the {@link RestOperations} used when requesting the Access
     * Token Response
     */
    public void setRestOperations(RestOperations restOperations) {
        Assert.notNull(restOperations, "restOperations cannot be null");
        this.restOperations = restOperations;
    }

}
