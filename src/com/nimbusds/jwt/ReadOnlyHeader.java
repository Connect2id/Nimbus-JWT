package com.nimbusds.jwt;


import java.util.Map;


/**
 * Read-only view of a {@link Header header}.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-22)
 */
public interface ReadOnlyHeader {


	/**
	 * Gets the type ({@code typ}) parameter.
	 *
	 * @return The type parameter, {@code null} if not specified.
	 */
	public Header.Type getType();
	
	
	/**
	 * Gets the mandatory algorithm ({@code alg}) parameter.
	 *
	 * @return The algorithm parameter.
	 */
	public JWA getAlgorithm();
	
	
	/**
	 * Gets the custom parameters.
	 *
	 * @return The custom parameters, empty map if none.
	 */
	public Map<String,Object> getCustomParameters();
}
