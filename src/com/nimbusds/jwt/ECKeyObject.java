package com.nimbusds.jwt;


import net.minidev.json.JSONObject;


/**
 * Elliptic curve JWK Key Object (immutable).
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-key-01">JWK draft 01</a>.
 * <p>See http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
 *
 * <p>Example JSON:
 * 
 * <pre>
 * { 
 *   "alg" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-19)
 */
public final class ECKeyObject extends JWKKeyObject {
	
	
	/**
	 * Enumeration of the supported cryptographic curves.
	 */
	public static enum Curve {
	
		
		/**
		 * P-256 curve.
		 */
		P_256("P-256"),
		
		
		/**
		 * P-384 curve.
		 */
		P_384("P-384"),
		
		
		/**
		 * P-521 curve.
		 */
		P_521("P-521");
		
		
		/**
		 * The canonical curve name.
		 */
		private String name;
		
		
		/**
		 * Creates a new cryptographic curve with the specified 
		 * canonical name.
		 *
		 * @param name The canonical curve name.
		 */
		private Curve(final String name) {
		
			this.name = name;
		}
		
		
		/**
		 * Returns the canonical name of this cryptographic curve.
		 *
		 * @return The canonical name.
		 */
		public String toString() {
		
			return name;
		}
	}
	
	
	/**
	 * The curve name.
	 */
	private final Curve crv;
	
	
	/**
	 * The x coordinate for the elliptic curve point.
	 */
	private final Base64URL x;
	
	
	/**
	 * The y coordinate for the elliptic curve point.
	 */
	private final Base64URL y;
	 
	
	/**
	 * Creates a new elliptic curve JWK Key Object with the specified 
	 * parameters.
	 *
	 * @param crv The cryptographic curve. Must not be {@code null}.
	 * @param x   The x coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param y   The y coordinate for the elliptic curve point. It is 
	 *            represented as the Base64URL encoding of the coordinate's 
	 *            big endian representation. Must not be {@code null}.
	 * @param use The use. {@code null} if not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 */
	public ECKeyObject(final Curve crv, final Base64URL x, final Base64URL y, 
	                   final Use use, final String kid) {
	
		super(JWKKeyObject.AlgorithmFamily.EC, use, kid);
		
		if (crv == null)
			throw new NullPointerException("The curve must not be null");
			
		this.crv = crv;
		
		if (x == null)
			throw new NullPointerException("The x coordinate must not be null");
		
		this.x = x;
		
		if (y == null)
			throw new NullPointerException("The y coordinate must not be null");
		
		this.y = y;
	}
	
	
	/**
	 * Gets the cryptographic curve.
	 *
	 * @return The cryptograhic curve.
	 */
	public Curve getCurve() {
	
		return crv;
	}
	
	
	/**
	 * Gets the x coordinate for the elliptic curve point. It is represented
	 * as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The x coordinate.
	 */
	public Base64URL getX() {
	
		return x;
	}
	
	
	/**
	 * Gets the y coordinate for the elliptic curve point. It is represented
	 * as the Base64URL encoding of the coordinate's big endian 
	 * representation.
	 *
	 * @return The y coordinate.
	 */
	public Base64URL getY() {
	
		return y;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		
		// Append EC specific attributes
		o.put("crv", crv.toString());
		o.put("x", x.toString());
		o.put("y", y.toString());
	
		return o;
	}
	
	
	/**
	 * Parses an elliptic curve JWK Key Object from the specified JSON 
	 * object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The resulting elliptic curve Key Object.
	 *
	 * @throws JWKException If the JWK Key Object couldn't be parsed.
	 */
	public static ECKeyObject parse(final JSONObject jsonObject)
		throws JWKException {
		
		if (jsonObject == null)
			throw new NullPointerException("The JSON object must not be null");
		
		// Parse the mandatory parameters first
		if (jsonObject.get("crv") == null || ! (jsonObject.get("crv") instanceof String))
			throw new JWKException("Missing, null or non-string \"crv\" member");

		if (jsonObject.get("x") == null || ! (jsonObject.get("x") instanceof String))
			throw new JWKException("Missing, null or non-string \"x\" member");
					
		if (jsonObject.get("y") == null || ! (jsonObject.get("y") instanceof String))
			throw new JWKException("Missing, null or non-string \"y\" member");
		
		String crvStr = (String)jsonObject.get("crv");
				
		ECKeyObject.Curve crv = null;

		if (crvStr.equals("P-256"))
			crv = ECKeyObject.Curve.P_256;

		else if (crvStr.equals("P-384"))
			crv = ECKeyObject.Curve.P_384;

		else if (crvStr.equals("P-521"))
			crv = ECKeyObject.Curve.P_521;
		else
			throw new JWKException("Invalid or unsupported elliptic curve \"crv\", must be \"P-256\", \"P-384\" or \"P-521\"");

		Base64URL x = new Base64URL((String)jsonObject.get("x"));
		Base64URL y = new Base64URL((String)jsonObject.get("y"));
		
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

		return new ECKeyObject(crv, x, y, use, keyID);
	}
}
