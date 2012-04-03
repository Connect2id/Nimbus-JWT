package com.nimbusds.jwt;


/**
 * Plain JSON Web Token (JWT).
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-26)
 */
public class PlainJWT extends JWT {

	
	/**
	 * The header.
	 */
	private PlainJWTHeader header;
	
	
	/**
	 * Creates a new plain JSON Web Token (JWT) with a default
	 * {@link PlainJWTHeader} and the specified claims set.
	 *
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public PlainJWT(final ClaimsSet claimsSet) {
		
		if (claimsSet == null)
			throw new NullPointerException("The claims set must not be null");
			
		this.claimsSet = claimsSet;
		
		header = new PlainJWTHeader();
	}
	
	
	/**
	 * Creates a new plain JSON Web Token (JWT) with the specified header
	 * and claims set.
	 *
	 * @param header    The plain JWT header. Must not be {@code null}.
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public PlainJWT(final PlainJWTHeader header, final ClaimsSet claimsSet) {
			
		if (header == null)
			throw new NullPointerException("The plain JWT header must not be null");
			
		this.header = header;
		
		if (claimsSet == null)
			throw new NullPointerException("The claims set must not be null");
		
		this.claimsSet = claimsSet;
	}
	
	
	/**
	 * Creates a new plain JSON Web Token (JWT) with the specified 
	 * serialised parts.
	 *
	 * @param firstPart  The first part, corresponding to the JWT header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the claims set.
	 *                   Must not be {@code null}.
	 *
	 * @throws JWTException If parsing of the serialised parts failed.
	 */
	public PlainJWT(final Base64URL firstPart, final Base64URL secondPart)
		throws JWTException {
	
		if (firstPart == null)
			throw new NullPointerException("The first part must not be null");
		
		try {
			this.header = PlainJWTHeader.parse(firstPart);
			
		} catch (HeaderException e) {
		
			throw new JWTException("Invalid or unsupported plain JWT header: " + e.getMessage(), e);
		}
		
		if (secondPart == null)
			throw new NullPointerException("The second part must not be null");
	
		this.claimsSet = new ClaimsSet(secondPart);
	}
	
	
	/**
	 * Gets the header of this JSON Web Token (JWT).
	 *
	 * @return The header.
	 */
	public ReadOnlyPlainJWTHeader getHeader() {
	
		return header;
	}
	
	
	/**
	 * Serialises this plain JSON Web Token (JWT) to its canonical format.
	 *
	 * <pre>
	 * [header-base64url].[claimsSet-base64url].[]
	 * </pre>
	 *
	 * @return The serialised plain JWT.
	 */
	public String serialize() {
	
		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');
		sb.append(claimsSet.toBase64URL().toString());
		sb.append('.');
		return sb.toString();
	}
	
	
	/**
	 * Parses a plain JSON Web Token (JWT).
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The parsed plain JWT.
	 *
	 * @throws JWTException If the string couldn't be parsed to a valid or
	 *                      supported JWT.
	 */
	public static PlainJWT parse(final String s)
		throws JWTException {
	
		Base64URL[] parts = JWT.split(s);
		
		if (! parts[2].toString().isEmpty())
			throw new JWTException("Unexpected third part of the JSON Web Token (JWT)");
		
		return new PlainJWT(parts[0], parts[1]);
	}
}
