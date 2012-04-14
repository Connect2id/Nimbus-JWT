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
 * JSON Web Encryption (JWE) header.
 *
 * <p>All standard reserved header parameters defined in JWE specification are
 * supported:
 *
 * <ul>
 *     <li>typ - optional for JWT, mandatory for nested JWS and JWE
 *     <li>alg - mandatory for plaintext, JWS and JWE
 *     <li>enc - optional
 *     <li>int - optional
 *     <li>iv - optional
 *     <li>epk - optional
 *     <li>zip - optional
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
 * <p>Example header:
 *
 * <pre>
 * {
 *   "typ" : "JWT",
 *   "alg" : "RSA1_5",
 *   "enc" : "A128GCM",
 *   "iv"  : "__79_Pv6-fg",
 *   "x5t" : "7noOPq-hJ1_hCnvWh6IeYI2w9Q0"
 * }
 * </pre>
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-01">JWE draft 01</a>
 *
 * @author Vladimir Dzhuvinov
 * @version 1.10 (2012-04-03)
 */
public class JWEHeader extends CommonSEHeader implements ReadOnlyJWEHeader {


	/**
	 * The encryption algorithm (applies to JWE, required for JWE).
	 */
	private JWA enc;
	
	
	/**
	 * The integrity algorithm {@code int} (applies to JWE, conditionally 
	 * optional).
	 */
	private JWA ia;
	
	
	/**
	 * The initialisation vector, Base64url (applies to JWE, optional).
	 */
	private Base64URL iv;
	
	
	/**
	 * The Ephemeral Public Key (applies to JWE, optional).
	 */
	private ECKeyObject epk;
	
	
	/**
	 * The compression algorithm, if any (applies to JWE, optional).
	 */
	private CompressionAlgorithm zip;
	
	
	/**
	 * Creates a new JSON Web Encryption (JWE) header.
	 *
	 * @param alg The encryption algorithm. Must not be {@code null}.
	 *
	 * @throws NullPointerException     If the algorithm is {@code null}.
	 * @throws IllegalArgumentException If the specified algorithm is not
	 *                                  for encryption.
	 */
	public JWEHeader(final JWA alg) {
	
		super(null, alg);
		
		if (alg == null)
			throw new NullPointerException("The algorithm must not be null");
		
		if (alg.getType() != JWA.Type.ENCRYPTION)
			throw new IllegalArgumentException("The algorithm is not for encryption");
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JWA getEncryptionMethod() {
	
		return enc;
	}
	
	
	/**
	 * Sets the encryption method ({@code enc}) parameter.
	 *
	 * @param enc The encryption method parameter, {@code null} if not 
	 *            specified.
	 *
	 * @throws IllegalArgumentException If the specified algorithm is not
	 *                                  for providing encryption.
	 */
	public void setEncryptionMethod(final JWA enc) {
	
		if (enc != null && ! enc.getType().equals(JWA.Type.ENCRYPTION))
			throw new IllegalArgumentException("The encryption method \"enc\" must be for encryption");
		
		this.enc = enc;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JWA getIntegrityAlgorithm() {
	
		return ia;
	}
	
	
	/**
	 * Sets the integrity algorithm ({@code int}) parameter.
	 *
	 * @param ia The integrity algorithm parameter, {@code null} if not 
	 *           specified.
	 */
	public void setIntegrityAlgorithm(final JWA ia) {
	
		this.ia = ia;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Base64URL getInitializationVector() {
	
		return iv;
	}
	
	
	/**
	 * Sets the initialization vector ({@code iv}) parameter.
	 *
	 * @param iv The initialization vector parameter, {@code null} if not 
	 *           specified.
	 */
	public void setInitializationVector(final Base64URL iv) {
	
		this.iv = iv;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public ECKeyObject getEphemeralPublicKey() {
	
		return epk;
	}
	
	
	/**
	 * Sets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @param epk The Ephemeral Public Key parameter, {@code null} if not 
	 *            specified.
	 */
	public void setEphemeralPublicKey(final ECKeyObject epk) {
	
		this.epk = epk;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public CompressionAlgorithm getCompressionAlgorithm() {
	
		return zip;
	}
	
	
	/**
	 * Sets the compression algorithm ({@code zip}) parameter.
	 *
	 * @param zip The compression algorithm parameter, {@code null} if not 
	 *            specified.
	 */
	public void setCompressionAlgorithm(final CompressionAlgorithm zip) {
	
		this.zip = zip;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
	
		if (enc != null)
			o.put("enc", enc.toString());
		
		if (ia != null)
			o.put("int", ia.toString());
		
		if (iv != null)
			o.put("iv", iv.toString());
		
		if (epk != null)
			o.put("epk", epk.toJSONObject());
		
		if (zip != null)
			o.put("zip", zip.toString());
		
		return o;
	}
	
	
	/**
	 * Parses a JWE header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The parsed JWE header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static JWEHeader parse(final JSONObject json)
		throws HeaderException {
	
		if (json == null)
			throw new HeaderException("The JSON object must not be null");
		
		
		// Get the "alg" parameter
		JWA alg = Header.parseAlgorithm(json);
		
		if (alg.getType() != JWA.Type.ENCRYPTION)
			throw new HeaderException("The \"alg\" parameter must be of type encryption");
		
		// Create a minimal header
		JWEHeader h = new JWEHeader(alg);
	
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
				else if (name.equals("enc")) {

					h.setEncryptionMethod(JWA.parse((String)value));
				}
				else if (name.equals("int")) {
				
					h.setIntegrityAlgorithm(JWA.parse((String)value));
				}
				else if (name.equals("iv")) {

					h.setInitializationVector(new Base64URL((String)value));
				}
				else if (name.equals("epk")) {

					h.setEphemeralPublicKey(ECKeyObject.parse((JSONObject)value));
				}
				else if (name.equals("zip")) {

					h.setCompressionAlgorithm(CompressionAlgorithm.parse((String)value));
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
					
					h.setX509CertChain(parseX509CertChain((JSONArray)value));
				}
				else {
					// Custom parameter
					customParameters.put(name, value);
				}
			
			} catch (ClassCastException e) {
			
				// All params
				throw new HeaderException("Unexpected JSON type of the \"" + name + "\" parameter", e);
				
			} catch (NoSuchAlgorithmException e) {
		
				// Integrity and encryption alg
				throw new HeaderException("Invalid or unsupported algorithm of the \"" + name + "\" parameter", e);
				
			} catch (IllegalArgumentException e) {
			
				// Passed not-encryption JWA for 'enc' parameter
				throw new HeaderException("Invalid or unsupported value of the \"" + name + "\" parameter", e);
				
			} catch (MalformedURLException e) {
			
				// All URL params
				throw new HeaderException("Invalid URL of the \"" + name + "\" parameter", e);
				
			} catch (HeaderException e) {
			
				// Cert chain
				throw new HeaderException("Invalid value of the \"" + name + "\" parameter", e);
				
			} catch (java.text.ParseException e) {
			
				// Type, compression alg
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
	 * Parses a JWE header from the specified JSON string.
	 *
	 * @param s The JSON string to parse, must not be {@code null}.
	 *
	 * @return The parsed JWE header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static JWEHeader parse(final String s)
		throws HeaderException {
		
		JSONObject json = Header.parseHeaderJSON(s);
		
		return parse(json);
	}
	
	
	/**
	 * Parses a JWE header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse, must not be {@code null}.
	 *
	 * @return The parsed JWE header.
	 *
	 * @throws HeaderException If the specified JSON object doesn't 
	 *                         represent a valid or supported header.
	 */
	public static JWEHeader parse(final Base64URL base64URL)
		throws HeaderException {
		
		if (base64URL == null)
			throw new HeaderException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
