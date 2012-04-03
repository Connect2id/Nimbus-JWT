package com.nimbusds.jwt;


/**
 * JSON Web Key (JWK) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.8 (2012-03-18)
 */
public class JWKException extends Exception {


	/**
	 * Creates a new JSON Web Key (JWK) exception with the specified
	 * message.
	 *
	 * @param message The exception message.
	 */
	public JWKException(final String message) {
		
		super(message);
	}
	
	
	/**
	 * Creates a new JSON Web Key (JWK) exception with the specified
	 * message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public JWKException(final String message, final Throwable cause) {
		
		super(message, cause);
	}
}
