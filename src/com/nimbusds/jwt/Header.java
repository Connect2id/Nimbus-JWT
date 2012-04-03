package com.nimbusds.jwt;


import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;


/**
 * The base abstract class for plain JWT, JWS and JWE headers.
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed alongside the supported ones, however 
 * will not be processed by this JWT implementation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-26)
 */
public abstract class Header implements ReadOnlyHeader {


	/**
	 * Enumeration of the supported header type ({@code typ}) values.
	 */
	public enum Type {
	
		/**
		 * Type ({@code typ}) parameter indicating a JWT.
		 *
		 * <p>Corresponds to the follwoing {@code typ} values:
		 *
		 * <ul>
		 *     <li>"JWT"
		 *     <li>"http://openid.net/specs/jwt/1.0"
		 * </ul>
		 */
		JWT,
		
		
		/**
		 * Type ({@code typ}) parameter indicating a nested JWS.
		 *
		 * <p>Corresponds to the following {@code typ} value:
		 *
		 * <ul>
		 *     <li>"JWS"
		 * </ul>
		 */
		JWS,
		
	
		/**
		 * Type ({@code typ}) parameter indicating a nested JWE.
		 *
		 * <p>Corresponds to the follwoing {@code typ} value:
		 *
		 * <ul>
		 *     <li>"JWE"
		 * </ul>
		 */
		JWE;
		
		
		/**
		 * Parses the specified type string (case sensitive).
		 *
		 * <p>Note that both "JWT" and "http://openid.net/specs/jwt/1.0" 
		 * resolve to {@link #JWT}.
		 *
		 * @param s The string to parse.
		 *
		 * @throws java.text.ParseException If the string couldn't be 
		 *                                  parsed to a supported JWT
		 *                                  header type.
		 */
		public static Type parse(final String s)
			throws java.text.ParseException {
		
			if (s == null)
				throw new NullPointerException("The parsed JWT header \"typ\" value must not be null");
			
			if (s.equals("JWT") || s.equals("http://openid.net/specs/jwt/1.0"))
				return JWT;
			
			if (s.equals("JWS"))
				return JWS;
			
			if (s.equals("JWE"))
				return JWE;
			
			throw new java.text.ParseException("Unsupported JWT header \"typ\" value: " + s, 0);
		}
	}
	
	
	/**
	 * The header type.
	 */
	private Type typ;
	
	
	/**
	 * The algorithm.
	 */
	private JWA alg;
	
	
	/**
	 * Custom header parameters (optional).
	 */
	private Map<String,Object> customParameters = new HashMap<String,Object>();
	
	
	/**
	 * Creates a new header with the specified type ({@code typ}) and 
	 * algorithm ({@code alg}) parameters.
	 *
	 * @param typ The type parameter, {@code null} if not specified.
	 * @param alg The algorithm parameter. Must not be {@code null}.
	 */
	protected Header(final Type typ, final JWA alg) {
	
		setType(typ);
		setAlgorithm(alg);
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Type getType() {
	
		return typ;
	}
	
	
	/**
	 * Sets the type ({@code typ}) parameter.
	 *
	 * @param typ The type parameter, {@code null} if not specified.
	 */
	public void setType(final Type typ) {
	
		this.typ = typ;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JWA getAlgorithm() {
	
		return alg;
	}
	
	
	/**
	 * Sets the mandatory type ({@code typ}) parameter.
	 *
	 * @param alg The algorithm parameter. Must not be {@code null}.
	 */
	public void setAlgorithm(final JWA alg) {
	
		if (alg == null)
			throw new NullPointerException("The algorithm \"alg\" must not be null");
		
		this.alg = alg;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Map<String,Object> getCustomParameters() {
	
		return customParameters;
	}
	
	
	/**
	 * Sets the custom parameters. The values must be serialisable to a JSON
	 * entity, otherwise will be ignored.
	 *
	 * @param customParameters The custom parameters, empty map or 
	 *                         {@code null} if none.
	 */
	public void setCustomParameters(final Map<String,Object> customParameters) {
	
		if (customParameters == null)
			return;
			
		this.customParameters = customParameters;
	}
	
	
	/**
	 * Returns a JSON object representation of this header. All custom
	 * parameters will be included if they serialise to a JSON entity and 
	 * their names don't conflict with the reserved ones.
	 *
	 * @return The JSON object representation of this header.
	 */
	public JSONObject toJSONObject() {
	
		// Include custom parameters, they may be overwritten if their
		// names match standard ones
		JSONObject o = new JSONObject(customParameters);
	
		if (typ != null)
			o.put("typ", typ.toString());
		
		// Alg is always defined
		o.put("alg", alg.toString());
		
		return o;
	}
	
	
	/**
	 * Returns a JSON string representation of this header. All custom
	 * parameters will be included if they serialise to a JSON entity and 
	 * their names don't conflict with the reserved ones.
	 *
	 * @return The JSON string representation of this header.
	 */
	public String toString() {
	
		return toJSONObject().toString();
	}
	
	
	/**
	 * Returns a Base64URL representation of this header.
	 *
	 * @return The Base64URL representation of thisheader.
	 */
	public Base64URL toBase64URL() {
	
		return Base64URL.encode(toString());
	}
	
	
	/**
	 * Parses a header JSON object from the specified string. Intended for
	 * initial parsing of plain JWT, JWS and JWE headers.
	 *
	 * @param s The string to parse, must not be {@code null}.
	 *
	 * @return The parsed JSON object.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a header.
	 */
	protected static JSONObject parseHeaderJSON(final String s)
		throws HeaderException {
		
		if (s == null)
			throw new HeaderException("The JSON string must not be null");
		
		JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);
		
		JSONObject json = null;
		
		try {
			json = (JSONObject)parser.parse(s);
			
		} catch (ParseException e) {
		
			throw new HeaderException("Invalid JSON: " + e.getMessage(), e);
			
		} catch (ClassCastException e) {
		
			throw new HeaderException("The header must be a JSON object");
		}
		
		if (json == null)
			throw new HeaderException("The header must be a JSON object");
		
		return json;
	}
	
	
	/**
	 * Parses an {@code alg} parameter from the specified header JSON 
	 * object. Intended for initial parsing of plain JWT, JWS and JWE headers.
	 *
	 * @param json The JSON object to parse, must not be {@code null}.
	 *
	 * @return The parsed algorithm.
	 *
	 * @throws HeaderException If the {@code alg} parameter couldn't be 
	 *                         parsed.
	 */
	protected static JWA parseAlgorithm(final JSONObject json)
		throws HeaderException {
		
		JWA alg = null;
		
		try {
			return JWA.parse((String)json.get("alg"));
			
		} catch (ClassCastException e) {
		
			throw new HeaderException("The header \"alg\" parameter value must be a string", e);
			
		} catch (NoSuchAlgorithmException e) {
		
			throw new HeaderException("Missing or unsupported header algorithm: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a {@link PlainJWTHeader}, {@link JWSHeader} or 
	 * {@link JWEHeader} from the specified JSON object.
	 *
	 * @param json The JSON object to parse, must not be {@code null}.
	 *
	 * @return The parsed header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static Header parse(final JSONObject json)
		throws HeaderException {
	
		if (json == null)
			throw new HeaderException("The JSON object must not be null");
		
		
		// Get the "alg" mandatory parameter
		JWA alg = null;
		
		try {
			alg = JWA.parse((String)json.get("alg"));
			
		} catch (ClassCastException e) {
		
			throw new HeaderException("The JWT \"alg\" parameter value must be a string", e);
			
		} catch (NoSuchAlgorithmException e) {
		
			throw new HeaderException("Missing or unsupported JWT algorithm: " + e.getMessage(), e);
		}
		
		switch (alg.getType()) {
		
			case NONE:
				return PlainJWTHeader.parse(json);
				
			case SIGNATURE:
				return JWSHeader.parse(json);
			
			case ENCRYPTION:
				return JWEHeader.parse(json);
			
			default:
				throw new HeaderException("Unsupported header type: " + alg.getType());
		}
	}
}
