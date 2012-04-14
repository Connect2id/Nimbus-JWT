package com.nimbusds.jwt;


import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;


/**
 * JSON Web Key (JWK), a JSON data structure that represents a set of 
 * {@link JWKKeyObject public keys}.
 *
 * <p>The JWK format is used to represent bare keys; representing certificate 
 * chains is an explicit non-goal of the JWK specification.  JSON Web Keys are 
 * can be used in {@link JWS JSON Web Signature} (JWS) using the 
 * {@link JWSHeader#getJWKURL "jku"} header parameter and in 
 * {@link JWE JSON Web Encryption} (JWE) using the 
 * {@link JWEHeader#getJWKURL "jku"} and 
 * {@link JWEHeader#getEphemeralPublicKey "epk"} (Ephemeral Public Key) 
 * header parameters.
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-key-01">JWK draft 01</a>.
 *
 * <p>Example JSON Web Key (JWK):
 *
 * <pre>
 * {"jwk":
 *   [
 *     {"alg":"EC",
 *	"crv":"P-256",
 *	"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *	"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *	"use":"enc",
 *	"kid":"1"},
 *
 *     {"alg":"RSA",
 *	"mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 * 4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 * tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 * QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 * SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 * w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *	"exp":"AQAB",
 *	"kid":"2011-04-29"}
 *   ]
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-03-26)
 */
public class JWK {


	/**
	 * The JWK Key Objects.
	 */
	private List<JWKKeyObject> koList = new LinkedList<JWKKeyObject>();
	
	
	/**
	 * Creates a new empty JSON Web Key (JWK).
	 */
	public JWK() {
	
		// Nothing to do
	}
	
	
	/**
	 * Creates a new JSON Web Key (JWK) with a single Key Object.
	 *
	 * @param ko The JWK Key Object. Must not be {@code null}.
	 */
	public JWK(final JWKKeyObject ko) {
	
		if (ko == null)
			throw new NullPointerException("The JWK Key Object must not be null");
		
		koList.add(ko);
	}
	
	
	/**
	 * Creates a new JSON Web Key (JWK) with the specified Key Objects.
	 *
	 * @param koList The JWK Key Object list. Must not be {@code null}.
	 */
	public JWK(final List<JWKKeyObject> koList) {
	
		if (koList == null)
			throw new NullPointerException("The JWK Key Object list must not be null");
		
		this.koList.addAll(koList);
	}
	
	
	/**
	 * Gets the list of the Key Objects in this JSON Web Key (JWK).
	 *
	 * @return The list of the Key Object, empty if none.
	 */
	public List<JWKKeyObject> getKeyObjectList() {
	
		return koList;
	}
	
	
	/**
	 * Returns a JSON object representation of this JSON Web Key (JWK).
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {
	
		JSONArray a = new JSONArray();
		
		Iterator <JWKKeyObject> it = koList.iterator();
		
		while (it.hasNext())
			a.add(it.next().toJSONObject());
		
		JSONObject o = new JSONObject();
		
		o.put("jwk", a);
		
		return o;
	}
	

	/**
	 * Returns the JSON object string representation of this JSON Web Key
	 * (JWK).
	 *
	 * @return The JSON object string representation.
	 */
	public String toString() {
	
		return toJSONObject().toString();
	}
	
	
	/**
	 * Parses the specified string representing a JSON Web Key (JWK).
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The parsed JSON Web Key (JWK).
	 *
	 * @throws JWKException If the string couldn't be parsed to a valid and
	 *                      supported JSON Web Key (JWK). Rich exception
	 *                      message.
	 */
	public static JWK parse(final String s)
		throws JWKException {
	
		if (s == null)
			throw new NullPointerException("The parsed JSON string must not be null");
		
		try {
			JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);
			
			return parse((JSONObject)parser.parse(s));
			
		} catch (ParseException e) {
		
			throw new JWKException("Invalid JSON: " + e.getMessage(), e);
		
		} catch (ClassCastException e) {
		
			throw new JWKException("The top level JSON entity must be an object");
		}
	}
	
	
	/**
	 * Parses the specified JSON object representing a JSON Web Key (JWK).
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The parsed JSON Web Key (JWK).
	 *
	 * @throws JWKException If the string couldn't be parsed to a valid and
	 *                      supported JSON Web Key (JWK). Rich exception 
	 *                      message.
	 */
	public static JWK parse(final JSONObject json)
		throws JWKException {
		
		if (json == null)
			throw new NullPointerException("The JSON object must not be null");
		
		if (! json.containsKey("jwk") || json.get("jwk") == null)
			throw new JWKException("Missing or null \"jwk\" member in the top level JSON object");
		
		JSONArray koArray = null;
		
		try {
			koArray = (JSONArray)json.get("jwk");
			
		} catch (ClassCastException e) {
		
			throw new JWKException("The \"jwk\" member must be a JSON array");
		}
		
		List<JWKKeyObject> koList = new LinkedList<JWKKeyObject>();
		
		for (int i=0; i < koArray.size(); i++) {
		
			if (! (koArray.get(i) instanceof JSONObject))
				throw new JWKException("The \"jwk\" JSON array must contain JSON objects only");
			
			JSONObject koJSON = (JSONObject)koArray.get(i);
			
			try {
				koList.add(JWKKeyObject.parse(koJSON));
				
			} catch (JWKException e) {
			
				throw new JWKException("Invalid or unsupported JWK Key Object at position " + i);
			}
		}
		
		return new JWK(koList);
	}
}
