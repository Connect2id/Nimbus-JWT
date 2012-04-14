package com.nimbusds.jwt;


import net.minidev.json.JSONObject;


/**
 * RSA JWK Key Object.
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-key-01">JWK draft 01</a>.
 * <p>See http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * <p>Example JSON:
 *
 * <pre>
 * {
 *   "alg" : "RSA",
 *   "mod" : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZC
 *            iFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5
 *            w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZg
 *            nYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt
 *            -bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIq
 *            bw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "exp" : "AQAB",
 *   "kid" : "2011-04-29"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-03-19)
 */
public final class RSAKeyObject extends JWKKeyObject {
	
	
	/**
	 * The modulus value for the RSA public key.
	 */
	private final Base64URL mod;
	
	
	/**
	 * The exponent value for the RSA public key.
	 */
	private final Base64URL exp;
	 
	
	/**
	 * Creates a new RSA JWK Key Object with the specified parameters.
	 *
	 * @param mod The the modulus value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param exp The the exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param use The use. {@code null} if not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 */
	public RSAKeyObject(final Base64URL mod, final Base64URL exp, 
	                   final Use use, final String kid) {
	
		super(JWKKeyObject.AlgorithmFamily.RSA, use, kid);
		
		if (mod == null)
			throw new NullPointerException("The modulus value must not be null");
		
		this.mod = mod;
		
		if (exp == null)
			throw new NullPointerException("The exponent value must not be null");
		
		this.exp = exp;
	}
	
	
	/**
	 * Returns the modulus value for the RSA public key. It is represented
	 * as the Base64URL encoding of the value's big ending representation.
	 *
	 * @return The RSA public key modulus.
	 */
	public Base64URL getModulus() {
	
		return mod;
	}
	
	
	/**
	 * Returns the exponent value for the RSA public key. It is represented
	 * as the Base64URL encoding of the value's big ending representation.
	 *
	 * @return The RSA public key exponent.
	 */
	public Base64URL getExponent() {
	
		return exp;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		
		// Append RSA public key specific attributes
		o.put("mod", mod.toString());
		o.put("exp", exp.toString());
	
		return o;
	}
	
	
	/**
	 * Parses an RSA JWK Key Object from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The resulting RSA Key Object.
	 *
	 * @throws JWKException If the JWK Key Object couldn't be parsed.
	 */
	public static RSAKeyObject parse(final JSONObject jsonObject)
		throws JWKException {
		
		if (jsonObject == null)
			throw new NullPointerException("The JSON object must not be null");
		
		// Parse the mandatory parameters first
		
		if (jsonObject.get("mod") == null || ! (jsonObject.get("mod") instanceof String))
			throw new JWKException("Missing, null or non-string \"mod\" member");
					
		if (jsonObject.get("exp") == null || ! (jsonObject.get("exp") instanceof String))
			throw new JWKException("Missing, null or non-string \"exp\" member");
					
		Base64URL mod = new Base64URL((String)jsonObject.get("mod"));
		Base64URL exp = new Base64URL((String)jsonObject.get("exp"));
		
		
		// Get optional "use"
		JWKKeyObject.Use use = null;

		if (jsonObject.get("use") != null) {

			if (! (jsonObject.get("use") instanceof String))
				throw new JWKException("The \"use\" member must be a string");

			String useStr = (String)jsonObject.get("use");

			if (useStr.equals("sig"))
				use = JWKKeyObject.Use.SIGNATURE;
			else if (useStr.equals("enc"))
				use = JWKKeyObject.Use.ENCRYPTION;
			else
				throw new JWKException("Invalid or unsupported key use \"use\", must be \"sig\" or \"enc\"");
		}


		// Get optional key ID
		String keyID = null;

		if (jsonObject.get("kid") != null) {

			if (! (jsonObject.get("kid") instanceof String))
				throw new JWKException("The \"kid\" member must be a string");

			keyID = (String)jsonObject.get("kid");
		}		
		
		return new RSAKeyObject(mod, exp, use, keyID);
	}
}
