package com.nimbusds.jwt;


import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;


/**
 * Plain JSON Web Token (JWT) header.
 *
 * <p>All standard reserved plain JWT header parameters are supported:
 *
 * <ul>
 *     <li>typ - optional, if specified should be "JWT" or 
 *         "http://openid.net/specs/jwt/1.0"
 *     <li>alg - mandatory, must be set to "none"
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed alongside the supported ones, however 
 * will not be processed by this JWT implementation.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "typ" : "JWT",
 *   "alg" : "none"
 * }
 * </pre>
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-03-26)
 */
public class PlainJWTHeader extends Header implements ReadOnlyPlainJWTHeader {


	/**
	 * Creates a new plain JSON Web Token (JWT) header. The type is set to
	 * {@link Header.Type#JWT} and the algorithm to {@link JWA#NONE}.
	 */
	public PlainJWTHeader() {
	
		super(Header.Type.JWT, JWA.NONE);
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @throws IllegalArgumentException If the type is not {@code null} or
	 *                                  {@link Header.Type#JWT}.
	 */
	public void setType(final Header.Type typ) {
	
		if (typ != null && typ != Header.Type.JWT)
			throw new IllegalArgumentException("The plain JWT header type must be null or JWT");
		
		super.setType(typ);
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @throws IllegaArgumentException If the algorithm is null or not 
	 *                                 {@link JWA#NONE}.
	 */
	public void setAlgorithm(final JWA alg) {
	
		if (alg == null || ! alg.equals(JWA.NONE))
			throw new IllegalArgumentException("The plain JWT header algorithm must be \"none\"");
		
		super.setAlgorithm(alg);
	}
	
	
	/**
	 * Parses a plain JWT header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The parsed JWT header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static PlainJWTHeader parse(final JSONObject json)
		throws HeaderException {
		
		if (json == null)
			throw new HeaderException("The JSON object must not be null");
		
		
		// Get the "alg" parameter
		JWA alg = Header.parseAlgorithm(json);
		
		if (alg != JWA.NONE)
			throw new HeaderException("The \"alg\" parameter must be \"none\"");
			
		
		// Create a minimal header, type may be set later
		PlainJWTHeader h = new PlainJWTHeader();
		
		
		// Get the optional type parameter
		
		Header.Type typ = null;
		
		try {
			typ = Header.Type.parse((String)json.get("typ"));
			
		} catch (ClassCastException e) {
		
			throw new HeaderException("The JWT \"typ\" header parameter value must be a string", e);
			
		} catch (java.text.ParseException e) {
		
			throw new HeaderException("Invalid or unsupported JWT \"typ\" header parameter: " + e.getMessage(), e);
		}
		
		
		if (typ != Header.Type.JWT)
			throw new HeaderException("The \"typ\" parameter must denote a JWT");
		
		h.setType(typ);
		
		
		// Parse custom parameters
		Map<String,Object> customParameters = new HashMap<String,Object>();
		
		Iterator<Map.Entry<String,Object>> it = json.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry<String,Object> entry = it.next();
			String name = entry.getKey();
			Object value = entry.getValue();
			
			if (name.equals("alg") || name.equals("typ") || value == null)
				continue;
			
			customParameters.put(name, value);
		}
		
		if (! customParameters.isEmpty())
			h.setCustomParameters(customParameters);
		
		return h;
	}
	
	
	/**
	 * Parses a plain JWT header from the specified JSON string.
	 *
	 * @param s The JSON string to parse, must not be {@code null}.
	 *
	 * @return The parsed plain JWT header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static PlainJWTHeader parse(final String s)
		throws HeaderException {
		
		JSONObject json = Header.parseHeaderJSON(s);
		
		return parse(json);
	}
	
	
	/**
	 * Parses a plain JWT header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse, must not be {@code null}.
	 *
	 * @return The parsed plain JWT header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static PlainJWTHeader parse(final Base64URL base64URL)
		throws HeaderException {
		
		if (base64URL == null)
			throw new HeaderException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
