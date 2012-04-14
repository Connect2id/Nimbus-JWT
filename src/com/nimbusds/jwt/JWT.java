package com.nimbusds.jwt;


import net.minidev.json.JSONObject;


/**
 * The base abstract class for {@link PlainJWT plain}, {@link SignedJWT signed}
 * and {@link EncryptedJWT encrypted} JSON Web Tokens (JWS).
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-01">JWS draft 01</a>
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-01">JWE draft 01</a>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-04-14)
 */
public abstract class JWT {


	/**
	 * The claims set.
	 */
	protected ClaimsSet claimsSet;
	
	
	/**
	 * Creates a new JSON Web Token (JWT).
	 */
	protected JWT() {
	
		claimsSet = null;
	}
	
	
	/**
	 * Creates a new JSON Web Token (JWT).
	 *
	 * @param claimsSet The claims set, {@code null} if not available (e.g
	 *                  for an encrypted JWT).
	 */
	protected JWT(final ClaimsSet claimsSet) {
	
		this.claimsSet = claimsSet;
	}
	
	
	/**
	 * Gets the claims set of this JWT.
	 *
	 * @return The claims set, {@code null} if not available (e.g. for an
	 *         encrypted JWT that isn't decrypted.
	 */
	public ClaimsSet getClaimsSet() {
	
		return claimsSet;
	}
	
	
	/**
	 * Serialises this JSON Web Token (JWT) to its canonical format.
	 *
	 * @return The serialised plain JWT.
	 *
	 * @throws IllegalStateException If the JWT is not in a state to allow
	 *                               serialisation.
	 */
	public abstract String serialize();
	
	
	/**
	 * Splits a serialised JSON Web Token (JWT) into its three Base64URL
	 * parts.
	 *
	 * @param s The serialised JWT to split. Must not be {@code null}.
	 *
	 * @return The JWT Base64URL parts (three for plain or signed JWT, four
	 *         for encrypted JWT).
	 *
	 * @throws JWTException If the specified string couldn't be split into
	 *                      three Base64URL parts.
	 */
	public static Base64URL[] split(final String s)
		throws JWTException {
		
		// We must have at least 2 dots but no more that 3
		
		// String.split() cannot handle empty parts
		final int dot1 = s.indexOf(".");
		
		if (dot1 == -1)
			throw new JWTException("Invalid serialized JSON Web Token (JWT): Missing part delimiters");
			
		final int dot2 = s.indexOf(".", dot1 + 1);
		
		if (dot2 == -1)
			throw new JWTException("Invalid serialized JSON Web Token (JWT): Missing second delimiter");
		
		// Third dot for JWE only
		final int dot3 = s.indexOf(".", dot2 + 1);
		
		if (dot3 != -1 && s.indexOf(".", dot3 + 1) != -1)
			throw new JWTException("Invalid serialized JSON Web Token (JWT): Too many part delimiters");
		
		
		if (dot3 == -1) {
			// Two dots - > three parts
			Base64URL[] parts = new Base64URL[3];
			parts[0] = new Base64URL(s.substring(0, dot1));
			parts[1] = new Base64URL(s.substring(dot1 + 1, dot2));
			parts[2] = new Base64URL(s.substring(dot2 + 1));
			return parts;
		}
		else {
			// Three dots -> four parts
			Base64URL[] parts = new Base64URL[4];
			parts[0] = new Base64URL(s.substring(0, dot1));
			parts[1] = new Base64URL(s.substring(dot1 + 1, dot2));
			parts[2] = new Base64URL(s.substring(dot2 + 1, dot3));
			parts[3] = new Base64URL(s.substring(dot3 + 1));
			return parts;
		}
	}


	/**
	 * Parses a plain, signed or encrypted JSON Web Token (JWT).
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The corresponding {@link PlainJWT}, {@link SignedJWT} or
	 *         {@link EncryptedJWT} instance.
	 *
	 * @throws JWTException If the string couldn't be parsed to a valid or
	 *                      supported JWT.
	 */
	public static JWT parse(final String s) 
		throws JWTException {
		
		Base64URL[] parts = split(s);
		
		JSONObject headerJSON = null;
		
		try {
			headerJSON = Header.parseHeaderJSON(parts[0].decodeToString());
			
		} catch (HeaderException e) {
		
			throw new JWTException("Invalid JWT header: " + e.getMessage(), e);
		}
		
		JWA alg = null;
		
		try {
			alg = Header.parseAlgorithm(headerJSON);
			
		} catch (HeaderException e) {
		
			throw new JWTException("Missing, invalid or unsupported JWT algorithm: " + e.getMessage(), e);
		}
		
		switch (alg.getType()) {
		
			case NONE:
				return PlainJWT.parse(s);
				
			case SIGNATURE:
				return SignedJWT.parse(s);
				
			case ENCRYPTION:
				return EncryptedJWT.parse(s);
			
			default:
				throw new JWTException("Couldn't determine type of algorithm " + alg);
		}
	}
}
