package com.nimbusds.jwt;


/**
 * Provides signing and verification of JSON Web Tokens (JWT) according to the 
 * JSON Web Signature (JWS) specification.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-30)
 */
public interface JWSService {


	/**
	 * Signs the specified content using the parameters in the header.
	 *
	 * @param header          The JSON Web Signature (JWS) header. Must not 
	 *                        be {@code null}.
	 * @param signableContent The content to sign. Must not be {@code null}.
	 *
	 * @return The JSON Web Signature (JWS) bytes, Base64URL-encoded.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public Base64URL sign(final ReadOnlyJWSHeader header, final byte[] signableContent)
		throws JWSException;

	/**
	 * Verifies the signature of the specified content using the parameters 
	 * in the header.
	 *
	 * @param header        The JSON Web Signature (JWS) header. Must not be 
	 *                      {@code null}.
	 * @param signedContent The signed content. Must not be {@code null}.
	 * @param signature     The JSON Web Signature (JWS) bytes, 
	 *                      Base64URL-encoded.
	 *
	 * @return {@code true} if the signature is successfully verified, else 
	 *         {@code false}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public boolean verify(final ReadOnlyJWSHeader header, final byte[] signedContent, final Base64URL signature)
		throws JWSException;
}
