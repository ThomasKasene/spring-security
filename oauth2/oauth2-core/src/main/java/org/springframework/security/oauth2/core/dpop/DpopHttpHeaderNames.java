package org.springframework.security.oauth2.core.dpop;

/**
 * Standard HTTP header field names defined by OAuth 2.0 Demonstrating Proof of Possession (DPoP).
 *
 * @author Thomas Kåsene
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-12.8" target="_blank">RFC 9449
 * Section 12.8 Hypertext Transfer Protocol (HTTP) Field Name Registration</a>
 */
public final class DpopHttpHeaderNames {

    /**
     * The HTTP {@code DPoP} header field name.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.1" target="_blank">Section 4.1 of RFC 9449</a>
     */
    public static final String DPOP = "DPoP";

    /**
     * The HTTP {@code DPoP-Nonce} header field name.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-8.2" target="_blank">Section 8.2 of RFC 9449</a>
     */
    public static final String DPOP_NONCE = "DPoP-Nonce";

    private DpopHttpHeaderNames() {
    }
}
