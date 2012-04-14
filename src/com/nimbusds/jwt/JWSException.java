package com.nimbusds.jwt;


/**
 * JSON Web Signature (JWS) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-03-20)
 */
public class JWSException extends Exception {


	/**
	 * Creates a new JSON Web Signature (JWS) exception with the specified
	 * message.
	 *
	 * @param message The exception message.
	 */
	public JWSException(final String message) {
		
		super(message);
	}
	
	
	/**
	 * Creates a new JSON Web Signature (JWS) exception with the specified
	 * message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public JWSException(final String message, final Throwable cause) {
		
		super(message, cause);
	}
}
