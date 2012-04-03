package com.nimbusds.jwt;


/**
 * Header exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-22)
 */
public class HeaderException extends Exception {


	/**
	 * Creates a new header exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public HeaderException(final String message) {
		
		super(message);
	}
	
	
	/**
	 * Creates a new header exception with the specified message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public HeaderException(final String message, final Throwable cause) {
		
		super(message, cause);
	}
}
