package com.nimbusds.jwt;


import java.net.URL;


/**
 * Read-only view of a {@link CommonSEHeader common JWS/JWE header}.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-20)
 */
public interface ReadOnlyCommonSEHeader extends ReadOnlyHeader {
	
	
	/**
	 * Gets the JSON Web Key (JWK) URL ({@code jku}) parameter.
	 *
	 * @return The JSON Web Key (JWK) URL parameter, {@code null} if not 
	 *         specified.
	 */
	public URL getJWKURL();
	
	
	/**
	 * Gets the key ID ({@code kid}) parameter.
	 *
	 * @return The key ID parameter, {@code null} if not specified.
	 */
	public String getKeyID();
	
	
	/**
	 * Gets the public key ({@code jpk}) parameter that corrsponds to the 
	 * key that is used to sign or encrypt the JWS/JWE.
	 *
	 * @return The public key parameter, {@code null} if not specified.
	 */
	public JWKKeyObject getPublicKey();
	
	
	/**
	 * Gets the X.509 certificate URL ({@code x5u}) parameter.
	 *
	 * @return The X.509 certificate URL parameter, {@code null} if not 
	 *         specified.
	 */
	public URL getX509CertURL();
	
	
	/**
	 * Gets the X.509 certificate thumbprint ({@code x5t}) parameter.
	 *
	 * @return The X.509 certificate thumbprint parameter, {@code null} if 
	 *         not specified.
	 */
	public Base64URL getX509CertThumbprint();
	
	
	/**
	 * Gets the X.509 certificate chain parameter ({@code x5c}) 
	 * corresponding to the key used to sign or encrypt the JWS/JWE.
	 *
	 * @return The X.509 certificate chain parameter, {@code null} if not
	 *         specified.
	 */
	public Base64[] getX509CertChain();	
}
