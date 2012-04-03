package com.nimbusds.jwt;


import java.net.URL;
import java.util.Arrays;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


/**
 * Common class for JWS and JWE headers.
 *
 * <p>Supports all standard reserved header parameters shared by the JWS and JWE
 * specifications:
 *
 * <ul>
 *     <li>typ - optional for JWT, mandatory for nested JWS and JWE
 *     <li>alg - mandatory for plaintext, JWS and JWE
 *     <li>jku - optional for JWS and JWE
 *     <li>kid - optional for JWS and JWE
 *     <li>jpk - optional for JWS and JWE
 *     <li>x5u - optional for JWS and JWE
 *     <li>x5t - optional for JWS and JWE
 *     <li>x5c - optional for JWS and JWE
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-22)
 */
public abstract class CommonSEHeader extends Header implements ReadOnlyCommonSEHeader {
	
	
	/**
	 * JSON Web Key (JWK) URL (applies to JWS + JWE, optional).
	 */
	private URL jku;
	
	
	/**
	 * Key ID (applies to JWS + JWE, optional).
	 */
	private String kid;
	
	
	/**
	 * The public key that corresponds to the key that was used to sign or
	 * encrypt the JWS/JWE (applies to JWS + JWE, optional).
	 */
	private JWKKeyObject jpk;
	
	
	/**
	 * X.509 public key certificate URL (applies to JWS + JWE, optional).
	 */
	private URL x5u;
	
	
	/**
	 * X.509 certificate thumbprint, Base64URL (SHA1) (applies to JWS + JWE,
	 * optional).
	 */
	private Base64URL x5t;
	
	
	/**
	 * The X.509 public key certificate or certificate chain corresponding 
	 * to the key used to sign or encrypt the JWS/JWE (applies to JWS + JWE,
	 * optional).
	 */
	private Base64[] x5c;
	

	/**
	 * Creates a new common JWS and JWE header with the specified type
	 * ({@code typ}) and algorithm ({@code alg}) parameters.
	 *
	 * @param typ The type parameter, {@code null} if not specified.
	 * @param alg The algorithm parameter. Must not be {@code null}.
	 */
	protected CommonSEHeader(final Header.Type typ, final JWA alg) {
	
		super(typ, alg);
	}
	
	
	/**
	 * @inheritDoc
	 */
	public URL getJWKURL() {
	
		return jku;
	}
	
	
	/**
	 * Sets the JSON Web Key (JWK) URL ({@code jku}) parameter.
	 *
	 * @param jku The JSON Web Key (JWK) URL parameter, {@code null} if not 
	 *            specified.
	 */
	public void setJWKURL(final URL jku) {
	
		this.jku = jku;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public String getKeyID() {
	
		return kid;
	}
	
	
	/**
	 * Sets the key ID ({@code kid}) parameter.
	 *
	 * @param kid The key ID parameter, {@code null} if not specified.
	 */
	public void setKeyID(final String kid) {
	
		this.kid = kid;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JWKKeyObject getPublicKey() {
	
		return jpk;
	}
	
	
	/**
	 * Sets the public key ({@code jpk}) parameter that corrsponds to the 
	 * key that is used to sign or encrypt the JWS/JWE.
	 *
	 * @param jpk The public key parameter, {@code null} if not specified.
	 */
	public void setPublicKey(final JWKKeyObject jpk) {
	
		this.jpk = jpk;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public URL getX509CertURL() {
	
		return x5u;
	}
	
	
	/**
	 * Sets the X.509 certificate URL ({@code x5u}) parameter.
	 *
	 * @param x5u The X.509 certificate URL parameter, {@code null} if not 
	 *            specified.
	 */
	public void setX509CertURL(final URL x5u) {
	
		this.x5u = x5u;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Base64URL getX509CertThumbprint() {
	
		return x5t;
	}
	
	
	/**
	 * Sets the X.509 certificate thumbprint ({@code x5t}) parameter.
	 *
	 * @param x5t The X.509 certificate thumbprint parameter, {@code null}  
	 *            if not specified.
	 */
	public void setX509CertThumbprint(final Base64URL x5t) {
	
		this.x5t = x5t;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Base64[] getX509CertChain() {
	
		return x5c;
	}
	
	
	/**
	 * Sets the X.509 certificate chain parameter ({@code x5c}) 
	 * corresponding to the key used to sign or encrypt the JWS/JWE.
	 *
	 * @param x5c The X.509 certificate chain parameter, {@code null} if not
	 *            specified.
	 */
	public void setX509CertChain(final Base64[] x5c) {
	
		this.x5c = x5c;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		
		if (jku != null)
			o.put("jku", jku.toString());
		
		if (kid != null)
			o.put("kid", kid);
		
		if (jpk != null)
			o.put("jpk", jpk.toJSONObject());
		
		if (x5u != null)
			o.put("x5u", x5u.toString());
		
		if (x5t != null)
			o.put("x5t", x5t.toString());
	
		if (x5c != null)
			o.put("x5c", Arrays.asList(x5c));
		
		return o;
	}
	
	
	/**
	 * Parses an X.509 certificate chain from the specified JSON array.
	 *
	 * @param jsonArray The JSON array to parse. Must not be {@code null}.
	 *
	 * @return The resulting X.509 certificate chain.
	 *
	 * @throws HeaderException If the X.509 certificate chain couldn't be
	 *                         parsed.
	 */
	protected static Base64[] parseX509CertChain(final JSONArray jsonArray)
		throws HeaderException {
		
		Base64[] chain = new Base64[jsonArray.size()];
		
		for (int i=0; i < jsonArray.size(); i++) {
		
			Object item = jsonArray.get(i);
			
			if (item == null)
				throw new HeaderException("The X.509 certificate at position " + i + " must not be null");
		
			if  (! (item instanceof String))
				throw new HeaderException("The X.509 certificate must be encoded as a Base64 string");
			
			chain[i] = new Base64((String)item);
		}
		
		return chain;
	}
}
