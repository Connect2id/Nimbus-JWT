package com.nimbusds.jwt;


/**
 * Read-only view of a {@link JWEHeader JWE header}.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-04-03)
 */
public interface ReadOnlyJWEHeader extends ReadOnlyCommonSEHeader {


	/**
	 * Gets the encryption method ({@code enc}) parameter.
	 *
	 * @return The encryption method parameter, {@code null} if not 
	 *         specified.
	 */
	public JWA getEncryptionMethod();
	
	
	/**
	 * Gets the integrity algorithm ({@code int}) parameter.
	 *
	 * @return The integrity algorithm parameter, {@code null} if not 
	 *         specified.
	 */
	public JWA getIntegrityAlgorithm();
	
	
	/**
	 * Gets the initialization vector ({@code iv}) parameter.
	 *
	 * @return The initialization vector parameter, {@code null} if not 
	 *         specified.
	 */
	public Base64URL getInitializationVector();
	
	
	/**
	 * Gets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @return The Ephemeral Public Key parameter, {@code null} if not 
	 *         specified.
	 */
	public ECKeyObject getEphemeralPublicKey();
	
	
	/**
	 * Gets the compression algorithm ({@code zip}) parameter.
	 *
	 * @return The compression algorithm parameter, {@code null} if not 
	 *         specified.
	 */
	public CompressionAlgorithm getCompressionAlgorithm();


}
