package com.nimbusds.jwt;


/**
 * JSON Web Encryption (JWE) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-20)
 */
public class JWEException extends Exception {


	/**
	 * Creates a new JSON Web Encryption (JWE) exception with the specified
	 * message.
	 *
	 * @param message The exception message.
	 */
	public JWEException(final String message) {
		
		super(message);
	}
	
	
	/**
	 * Creates a new JSON Web Encryption (JWE) exception with the specified
	 * message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public JWEException(final String message, final Throwable cause) {
		
		super(message, cause);
	}
}
