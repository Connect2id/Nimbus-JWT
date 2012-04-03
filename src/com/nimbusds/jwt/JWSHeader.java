package com.nimbusds.jwt;


import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;


/**
 * JSON Web Signature (JWS) header.
 *
 * <p>All standard reserved header parameters defined in JWS specification are
 * supported:
 *
 * <ul>
 *     <li>typ - optional for JWT, mandatory for nested JWS and JWE
 *     <li>alg - mandatory
 *     <li>jku - optional
 *     <li>kid - optional
 *     <li>jpk - optional
 *     <li>x5u - optional
 *     <li>x5t - optional
 *     <li>x5c - optional
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed alongside the supported ones, however 
 * will not be processed by this JWT implementation.
 *
 * <p>Example header of a signed JSON Web Token (JWT) using the 
 * {@link JWA#HS256 HMAC SHA-256 algorithm}:
 *
 * <pre>
 * {
 *   "typ" : "JWT",
 *   "alg" : "HS256"
 * }
 * </pre>
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-01">JWS draft 01</a>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-26)
 */
public class JWSHeader extends CommonSEHeader implements ReadOnlyJWSHeader {


	/**
	 * Creates a new JSON Web Signature (JWS) header.
	 *
	 * @param alg The signature algorithm. Must not be {@code null}.
	 *
	 * @throws NullPointerException     If the algorithm is {@code null}.
	 * @throws IllegalArgumentException If the specified algorithm is not
	 *                                  for signatures.
	 */
	public JWSHeader(final JWA alg) {
	
		super(null, alg);
		
		if (alg == null)
			throw new NullPointerException("The algorithm must not be null");
		
		if (alg.getType() != JWA.Type.SIGNATURE)
			throw new IllegalArgumentException("The algorithm is not for signatures");
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @throws IllegaArgumentException If the algorithm is null or not 
	 *                                 {@link JWA.Type#SIGNATURE}.
	 */
	public void setAlgorithm(final JWA alg) {
	
		if (alg == null || ! alg.getType().equals(JWA.Type.SIGNATURE))
			throw new IllegalArgumentException("The JWS header algorithm must be for signatures");
		
		super.setAlgorithm(alg);
	}
	
	
	/**
	 * Parses a JWS header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The parsed JWS header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static JWSHeader parse(final JSONObject json)
		throws HeaderException {
	
		if (json == null)
			throw new HeaderException("The JSON object must not be null");
		
		
		// Get the "alg" parameter
		JWA alg = Header.parseAlgorithm(json);
		
		if (alg.getType() != JWA.Type.SIGNATURE)
			throw new HeaderException("The \"alg\" parameter must be of type signature");
		
		// Create a minimal header
		JWSHeader h = new JWSHeader(alg);
		
		
		// Parse optional + custom parameters
		Map<String,Object> customParameters = new HashMap<String,Object>();
		
		Iterator<Map.Entry<String,Object>> it = json.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry<String,Object> entry = it.next();
			String name = entry.getKey();
			Object value = entry.getValue();
			
			if (value == null)
				continue;
			
			try {
				if (name.equals("typ")) {

					h.setType(Type.parse((String)value));
				}
				else if (name.equals("jku")) {

					h.setJWKURL(new URL((String)value));
				}
				else if (name.equals("kid")) {
				
					h.setKeyID((String)value);
				}
				else if (name.equals("jpk")) {
				
					h.setPublicKey(JWKKeyObject.parse((JSONObject)value));
				}
				else if (name.equals("x5u")) {

					h.setX509CertURL(new URL((String)value));
				}
				else if (name.equals("x5t")) {

					h.setX509CertThumbprint(new Base64URL((String)value));
				}
				else if (name.equals("x5c")) {
					
					h.setX509CertChain(CommonSEHeader.parseX509CertChain((JSONArray)value));
				}
				else {
					// Custom parameter
					customParameters.put(name, value);
				}
			
			} catch (ClassCastException e) {
			
				// All params
				throw new HeaderException("Unexpected JSON type of the \"" + name + "\" parameter", e);
				
			} catch (MalformedURLException e) {
			
				// All URL params
				throw new HeaderException("Invalid URL of the \"" + name + "\" parameter", e);
				
			} catch (HeaderException e) {
			
				// Cert chain
				throw new HeaderException("Invalid value of the \"" + name + "\" parameter", e);
				
			} catch (java.text.ParseException e) {
			
				// Type
				throw new HeaderException("Invalid or unsupported value of the \"" + name + "\" parameter", e);
			
			} catch (JWKException e) {
			
				// On epk or key object parse exception
				throw new HeaderException("Couldn't parse the JWK Key Object of the \"" + name + "\" parameter", e);
			}
		}
		
		if (! customParameters.isEmpty())
			h.setCustomParameters(customParameters);
		
		return h;
	}
	
	
	/**
	 * Parses a JWS header from the specified JSON string.
	 *
	 * @param s The JSON string to parse, must not be {@code null}.
	 *
	 * @return The parsed JWS header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static JWSHeader parse(final String s)
		throws HeaderException {
		
		JSONObject json = Header.parseHeaderJSON(s);
		
		return parse(json);
	}
	
	
	/**
	 * Parses a JWS header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse, must not be {@code null}.
	 *
	 * @return The parsed JWS header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static JWSHeader parse(final Base64URL base64URL)
		throws HeaderException {
		
		if (base64URL == null)
			throw new HeaderException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
