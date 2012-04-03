package com.nimbusds.jwt;


/**
 * JSON Web Token (JWT) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-02)
 */
public class JWTException extends Exception {


	/**
	 * Creates a new JSON Web Token (JWT) exception with the specified
	 * message.
	 *
	 * @param message The exception message.
	 */
	public JWTException(final String message) {
		
		super(message);
	}
	
	
	/**
	 * Creates a new JSON Web Token (JWT) exception with the specified
	 * message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public JWTException(final String message, final Throwable cause) {
		
		super(message, cause);
	}
}
