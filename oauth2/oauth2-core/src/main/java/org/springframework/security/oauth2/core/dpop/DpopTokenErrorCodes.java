package org.springframework.security.oauth2.core.dpop;

/**
 * Standard error codes defined by OAuth 2.0 Demonstrating Proof of Possession (DPoP).
 *
 * @author Thomas Kåsene
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-12.8" target="_blank">RFC 9449
 * Section 12.8: Hypertext Transfer Protocol (HTTP) Field Name Registration</a>
 */
public final class DpopTokenErrorCodes {

    /**
     * {@code use_dpop_nonce} - the DPoP proof is missing a server-provided DPoP nonce, or includes
     * an expired one.
     */
    public static final String USE_DPOP_NONCE = "use_dpop_nonce";

    /**
     * {@code invalid_dpop_proof} - the DPoP proof is considered invalid as per
     * <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.3" target="_blank">RFC 9449
     * Section 4.3 Checking for Proofs</a>.
     */
    public static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";

    private DpopTokenErrorCodes() {
    }
}
