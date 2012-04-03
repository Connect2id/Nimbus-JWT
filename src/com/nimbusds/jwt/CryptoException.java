package com.nimbusds.jwt;


/**
 * Cryptographic exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-09)
 */
public class CryptoException extends Exception {


	/**
	 * Creates a new cryptographic exception.
	 */
	public CryptoException() {
	}
	
	
	/**
	 * Creates a new cryptographic exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public CryptoException(final String message) {
	
        	super(message);
	}
	
	
	/**
	 * Creates a new cryptographic exception with the specified message and
	 * cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public CryptoException(final String message, final Throwable cause) {
	
		super(message, cause);
	}
	

	/**
	 * Creates a new cryptographic exception with the specified cause.
	 *
	 * @param cause   The exception cause.
	 */
	public CryptoException(final Throwable cause) {
	
		super(cause);
	}
}

