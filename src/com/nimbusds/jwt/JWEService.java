package com.nimbusds.jwt;


/**
 * Provides encryption and decryption of JSON Web Tokens (JWT) according to the 
 * JSON Web Encryption (JWE) specification.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-04-02)
 */
public interface JWEService {


	/**
	 * Encrypts the specified clear text using the parameters in the header.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must not be
	 *                  {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 *
	 * @return The encrypted parts.
	 *
	 * @throws JWEException If encryption failed for some reason.
	 */
	public JWE.Parts encrypt(final ReadOnlyJWEHeader header, 
	                         final byte[] clearText)
		throws JWEException;
	
	
	/**
	 * Decrypts the specified cipher text using the parameters in the header.
	 *
	 * @param header         The JSON Web Encryption (JWE) header. Must not be
	 *                       {@code null}.
	 * @param encryptedKey   The encrypted key. {@code null} if not required
	 *                       by the JWE algorithm.
	 * @param cipherText     The cipher text to decrypt. Must not be 
	 *                       {@code null}.
	 * @param integrityValue The integrity value. {@code null} if not 
	 *                       required by the JWE algorithm.
	 *
	 * @return The clear text.
	 *
	 * @throws JWEException If decryption failed for some reason.
	 */
	public byte[] decrypt(final ReadOnlyJWEHeader header, 
	                      final Base64URL encryptedKey,
			      final Base64URL cipherText,
			      final Base64URL integrityValue)
		throws JWEException;
}
