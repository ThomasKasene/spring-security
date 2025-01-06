package org.springframework.security.oauth2.core.dpop;

/**
 * The claim names that may be contained in the DPoP proof JWT, as defined by the OAuth 2.0 Demonstrating
 * Proof of Possession (DPoP) specification.
 *
 * @author Thomas Kåsene
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.2" target="_blank">RFC 9449
 * Section 4.2 DPoP Proof JWT Syntax</a>
 */
public final class DpopProofJwtClaimNames {

    /**
     * {@code jti} - unique identifier for the DPoP proof JWT
     */
    public static final String JTI = "jti";

    /**
     * {@code iat} - creation timestamp of the JWT
     */
    public static final String IAT = "iat";

    /**
     * {@code htm} - the value of the HTTP method of the request to which the JWT is attached
     */
    public static final String HTM = "htm";

    /**
     * {@code htu} - the HTTP target URI of the request to which the JWT is attached, without query
     * and fragment parts
     */
    public static final String HTU = "htu";

    /**
     * {@code ath} - hash of the access token
     */
    public static final String ATH = "ath";

    /**
     * {@code nonce} - a recent nonce provided via the {@code DPoP-Nonce} HTTP header
     */
    public static final String NONCE = "nonce";

    private DpopProofJwtClaimNames() {
    }
}
