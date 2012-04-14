package com.nimbusds.jwt;


import java.io.UnsupportedEncodingException;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;


/**
 * Claims set with JSON object, string, byte array and Base64URL views.
 *
 * <p>All views are created on demand to conserve resources.
 *
 * <p>UTF-8 is the character set for all string from / to byte array 
 * conversions.
 *
 * <p>Conversion relations:
 *
 * <pre>
 * JSONObject <=> String <=> Base64URL
 *                       <=> byte[]
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-03-17)
 */
public class ClaimsSet {


	/**
	 * Enumeration of the origin data types used to create a claims set.
	 */
	public static enum Origin {
	
		/**
		 * The claims set was created from a JSON object.
		 */
		JSON,
		
		
		/**
		 * The claims set was created from a JSON object string.
		 */
		STRING,
		
		
		/**
		 * The claims set was created from a byte array representing a 
		 * JSON object string.
		 */
		BYTE_ARRAY,
		
		
		/**
		 * The claims set was created from a Base64URL representing a
		 * JSON object string.
		 */
		BASE64URL;
	}
	

	/**
	 * UTF-8 is the character set for all string from / to byte array
	 * conversions.
	 */
	private static final String CHARSET = "UTF-8";
	
	
	/**
	 * The original date type.
	 */
	private Origin origin;
	
	
	/**
	 * The JSON object view.
	 */
	private JSONObject jsonView = null;
	
	
	/**
	 * The string view.
	 */
	private String stringView = null;
	
	
	/**
	 * The byte array view.
	 */
	private byte[] bytesView = null;
	
	
	/**
	 * The Base64URL view.
	 */
	private Base64URL base64URLView = null;
	
	
	/**
	 * Parses the specified JSON object.
	 *
	 * @param s The string representation of the JSON object. May be
	 *          {@code null}.
	 *
	 * @return The parsed JSON object, {@code null} if parsing failed.
	 */
	private static JSONObject parseJSONObject(final String s) {
	
		if (s == null)
			return null;
	
		try {
			JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);
				
			return (JSONObject)parser.parse(s);
			
		} catch (ParseException e) {
			
			return null;
			
		} catch (ClassCastException e) {
		
			return null;
		}
	}
	
	
	/**
	 * Converts a byte array to a string using {@link #CHARSET}.
	 *
	 * @param bytes The byte array to convert. May be {@code null}.
	 *
	 * @return The resulting string, {@code null} if conversion failed.
	 */
	private static String byteArrayToString(final byte[] bytes) {
	
		if (bytes == null)
			return null;
	
		try {
			return new String(bytes, CHARSET);
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
			return null;
		}
	}
	
	
	/**
	 * Converts a stirng to a byte array using {@link #CHARSET}.
	 *
	 * @param stirng The string to convert. May be {@code null}.
	 *
	 * @return The resulting byte array, {@code null} if conversion failed.
	 */
	private static byte[] stringToByteArray(final String string) {
	
		if (string == null)
			return null;
	
		try {
			return string.getBytes(CHARSET);
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
			return null;
		}
	}
	
	
	/**
	 * Creates a new claims set.
	 *
	 * @param json A JSON object representing the claims set. Must not be
	 *             {@code null}.
	 */
	public ClaimsSet(final JSONObject json) {
	
		if (json == null)
			throw new NullPointerException("The JSON object must not be null");
			
		jsonView = json;
		
		origin = Origin.JSON;
	}
	
	
	/**
	 * Creates a new claims set.
	 *
	 * @param string A JSON object string representing the claims set. Must 
	 *               not be {@code null}.
	 */
	public ClaimsSet(final String string) {
	
		if (string == null)
			throw new NullPointerException("The JSON object string must not be null");
			
		stringView = string;
		
		origin = Origin.STRING;
	}
	
	
	/**
	 * Creates a new claims set.
	 *
	 * @param bytes A JSON object string converted to bytes representing the
	 *              claims set. Must not be {@code null}.
	 */
	public ClaimsSet(final byte[] bytes) {
	
		if (bytes == null)
			throw new NullPointerException("The JSON object string bytes must not be null");
			
		bytesView = bytes;
		
		origin = Origin.BYTE_ARRAY;
	}
	
	
	/**
	 * Creates a new claims set.
	 *
	 * @param base64URL A Base64URL-encoded JSON object string representing 
	 *                  the claims set. Must not be {@code null}.
	 */
	public ClaimsSet(final Base64URL base64URL) {
	
		if (base64URL == null)
			throw new NullPointerException("The Base64URL-encoded JSON object string must not be null");
			
		base64URLView = base64URL;
		
		origin = Origin.BASE64URL;
	}
	
	
	/**
	 * Gets the date type used to create this claims set.
	 *
	 * @return The origin data type.
	 */
	public Origin getOrigin() {
	
		return origin;
	}
	
	
	/**
	 * Returns a JSON object view of this claims set.
	 *
	 * @return The JSON object view, {@code null} if the claims set couldn't
	 *         be converted to a JSON object.
	 */
	public JSONObject toJSONObject() {
	
		if (jsonView != null)
			return jsonView;
		
		// Convert
		if (stringView != null) {
		
			jsonView = parseJSONObject(stringView);
		}
		else if (bytesView != null) {
		
			stringView = byteArrayToString(bytesView);
			jsonView = parseJSONObject(stringView);
		}
		else if (base64URLView != null) {
			
			stringView = base64URLView.decodeToString();
			jsonView = parseJSONObject(stringView);
		}
		
		return jsonView;
	}
	
	
	/**
	 * Returns a string view of this claims set.
	 *
	 * @return The string view.
	 */
	public String toString() {
	
		if (stringView != null)
			return stringView;

		// Convert
		if (jsonView != null) {
		
			stringView = jsonView.toString();
		}
		else if (bytesView != null) {
		
			stringView = byteArrayToString(bytesView);
		}
		else if (base64URLView != null) {
			
			stringView = base64URLView.decodeToString();
		}
		
		return stringView;
	}
	
	
	/**
	 * Returns a byte array view of this claims set.
	 *
	 * @return The byte array view.
	 */
	public byte[] toBytes() {
	
		if (bytesView != null)
			return bytesView;
		
		// Convert
		if (stringView != null) {
		
			bytesView = stringToByteArray(stringView);
		}		
		else if (jsonView != null) {
		
			stringView = jsonView.toString();
			bytesView = stringToByteArray(stringView);
		}
		else if (base64URLView != null) {
		
			bytesView = base64URLView.decode();
		}
		
		return bytesView;	
	}
	
	
	/**
	 * Returns a Base64URL view of this claims set.
	 *
	 * @return The Base64URL view.
	 */
	public Base64URL toBase64URL() {
	
		if (base64URLView != null)
			return base64URLView;
		
		// Convert
		
		if (stringView != null) {
		
			base64URLView = Base64URL.encode(stringView);
		
		}
		else if (bytesView != null) {
		
			base64URLView = Base64URL.encode(bytesView);
			
		}
		else if (jsonView != null) {
		
			stringView = jsonView.toString();
			base64URLView = Base64URL.encode(stringView);
		}
		
		return base64URLView;
	}
}
