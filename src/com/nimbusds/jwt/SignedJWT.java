package com.nimbusds.jwt;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


/**
 * Signed JSON Web Token (JWT).
 *
 * <p>The actual signing and verification is provided by the {@link JWE} class.
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>.
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-01">JWS draft 01</a>.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-30)
 */
public class SignedJWT extends JWT {


	/**
	 * Enumeration of the states of a signed JSON Web Token (JWT).
	 */
	public static enum State {
	
		/**
		 * The JWT is not signed yet.
		 */
		UNSIGNED,
		
		
		/**
		 * The JWT is signed but not verified.
		 */
		SIGNED,
		
		
		/**
		 * The JWT is signed and verified.
		 */
		VERIFIED;
	}
	
	
	/**
	 * The header.
	 */
	private JWSHeader header;
	
	
	/**
	 * The signable content of this JSON Web Token (JWT).
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[claimsSet-base64url]
	 * </pre>
	 */
	private byte[] signableContent;
	
	
	/**
	 * The signature, {@code null} if unsigned.
	 */
	private Base64URL signature;
	
	
	/**
	 * The state.
	 */
	private State state;
	
	
	/**
	 * Creates a new to-be-signed JSON Web Token (JWT) with the specified 
	 * header and claims set. The initial state will be 
	 * {@link State#UNSIGNED unsigned}.
	 *
	 * @param header    The JWS header. Must not be {@code null}.
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public SignedJWT(final JWSHeader header, final ClaimsSet claimsSet) {
	
		if (header == null)
			throw new NullPointerException("The JWS header must not be null");
			
		this.header = header;
		
		if (claimsSet == null)
			throw new NullPointerException("The claims set must not be null");
		
		this.claimsSet = claimsSet;
		
		setSignableContent(header.toBase64URL(), claimsSet.toBase64URL());
		
		signature = null;
		
		state = State.UNSIGNED;
	}
	
	
	/**
	 * Creates a new signed JSON Web Token (JWT) with the specified 
	 * serialised parts. The state will be {@link State#SIGNED signed}.
	 *
	 * @param firstPart  The first part, corresponding to the JWS header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the claims set.
	 *                   Must not be {@code null}.
	 * @param thirdPart  The third part, corresponding to the signature.
	 *                   Must not be {@code null}.
	 *
	 * @throws JWTException If parsing of the serialised parts failed.
	 */
	public SignedJWT(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart)	
		throws JWTException {
	
		if (firstPart == null)
			throw new NullPointerException("The first part must not be null");
		
		try {
			this.header = JWSHeader.parse(firstPart);
			
		} catch (HeaderException e) {
		
			throw new JWTException("Invalid or unsupported JWS header: " + e.getMessage(), e);
		}
		
		if (secondPart == null)
			throw new NullPointerException("The second part must not be null");
	
		this.claimsSet = new ClaimsSet(secondPart);
		
		setSignableContent(firstPart, secondPart);
	
		if (thirdPart == null)
			throw new NullPointerException("The third part must not be null");
		
		signature = thirdPart;
		
		state = State.SIGNED; // but not verified yet!
	}
	
	
	/**
	 * Gets the header of this JSON Web Token (JWT).
	 *
	 * @return The header.
	 */
	public ReadOnlyJWSHeader getHeader() {
	
		return header;
	}
	
	
	/**
	 * Sets the signable content of this JSON Web Token (JWT).
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[claimsSet-base64url]
	 * </pre>
	 *
	 * @param firstPart  The first part, corresponding to the JWS header.
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the claims set.
	 *                   Must not be {@code null}.
	 */
	private void setSignableContent(final Base64URL firstPart, final Base64URL secondPart) {
	
		StringBuilder sb = new StringBuilder(firstPart.toString());
		sb.append('.');
		sb.append(secondPart.toString());

		try {
			signableContent = sb.toString().getBytes("UTF-8");
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
		}
	}
	
	
	/**
	 * Gets the signable content of this JSON Web Token (JWT).
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[claimsSet-base64url]
	 * </pre>
	 *
	 * @return The signable content, ready for passing to the JSON Web
	 *         Signature (JWS) service.
	 */
	public byte[] getSignableContent() {
	
		return signableContent;
	}
	
	
	/**
	 * Gets the signature of this JSON Web Token (JWT).
	 *
	 * @return The signature, {@code null} if the token is not signed yet.
	 */
	public Base64URL getSignature() {
	
		return signature;
	}
	
	
	/**
	 * Gets the state of this JSON Web Token (JWT).
	 *
	 * @return The state.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Ensures the current state is {@link State#UNSIGNED unsigned}.
	 *
	 * @throws IllegalStateException If the current state is not unsigned.
	 */
	private void ensureUnsignedState() {
	
		if (state != State.UNSIGNED)
			throw new IllegalStateException("The JWT must be in an unsigned state");
	}
	
	
	/**
	 * Ensures the current state is {@link State#SIGNED signed} or
	 * {@link State#VERIFIED verified}.
	 *
	 * @throws IllegalStateException If the current state is not signed or
	 *                               verified.
	 */
	private void ensureSignedOrVerifiedState() {
	
		if (state != State.SIGNED && state != State.VERIFIED)
			throw new IllegalStateException("The JWT must be in a signed or verified state");
	}
	
	
	/**
	 * Signs this JSON Web Token (JWT) using the specified JWS service. The
	 * JWT must be in a {@link State#UNSIGNED unsigned} state.
	 *
	 * @param service The JWS service to use to sign this JWT. Must not be
	 *                {@code null}.
	 *
	 * @throws JWSException If the JWT couldn't be signed.
	 */
	public void sign(final JWSService service)
		throws JWSException {
	
		if (service == null)
			throw new NullPointerException("The JWS service must not be null");
	
		ensureUnsignedState();
		
		signature = service.sign(getHeader(), getSignableContent());
	
		state = State.SIGNED;
	}
	
	
	/**
	 * Signs this JSON Web Token (JWT) using the specified HMAC shared
	 * secret. The JWT must be in a {@link State#UNSIGNED unsigned} state
	 * and its algorithm header one of the following:
	 *
	 * <ul>
	 *     <li>{@link JWA#HS256} (mandatory for JWS implementations)
	 *     <li>{@link JWA#HS384} 
	 *     <li>{@link JWA#HS512}
	 * </ul>
	 *
	 * @param sharedSecret The HMAC shared secret. Must not be {@code null}.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public void hmacSign(final byte[] sharedSecret)
		throws JWSException {
		
		ensureUnsignedState();
		
		signature = JWS.hmacSign(getHeader(), getSignableContent(), sharedSecret);
		
		state = State.SIGNED;
	}
	
	
	/**
	 * Signs this JSON Web Token (JWT) using the specified private RSA key.
	 * The JWT must be in a {@link State#UNSIGNED unsigned} state and its 
	 * algorithm header one of the following:
	 *
	 * <ul>
	 *     <li>{@link JWA#RS256} (recommended for JWS implementations)
	 *     <li>{@link JWA#RS384}
	 *     <li>{@link JWA#RS512}
	 * </ul>
	 *
	 * @param privateKey The private RSA key. Must not be {@code null}.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public void rsaSign(final RSAPrivateKey privateKey)
		throws JWSException {
		
		ensureUnsignedState();
		
		signature = JWS.rsaSign(getHeader(), getSignableContent(), privateKey);
		
		state = State.SIGNED;
	}
	
	
	/**
	 * Signs this JSON Web Token (JWT) using the specified elliptic curve
	 * private key. The JWT must be in a {@link State#UNSIGNED unsigned} 
	 * state and its algorithm header one of the following:
	 *
	 * <ul>
	 *     <li>{@link JWA#ES256} (recommended for JWS implementations)
	 *     <li>{@link JWA#ES384}
	 *     <li>{@link JWA#ES512}
	 * </ul>
	 *
	 * @param privateKey The private key (D). Must not be {@code null}.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public void ecdsaSign(final BigInteger privateKey)
		throws JWSException {
		
		ensureUnsignedState();
		
		signature = JWS.ecdsaSign(getHeader(), getSignableContent(), privateKey);
		
		state = State.SIGNED;
	}
	
	
	/**
	 * Verifies the signature of this JSON Web Token (JWT) using the 
	 * specified JWS service. The JWT must be in a {@link State#SIGNED 
	 * signed} state.
	 *
	 * @param service The JWS service to use to verify this JWT. Must not be
	 *                {@code null}.
	 *
	 * @throws JWSException If the JWT couldn't be signed.
	 */
	public boolean verify(final JWSService service)
		throws JWSException {
	
		if (service == null)
			throw new NullPointerException("The JWS service must not be null");
		
		ensureSignedOrVerifiedState();
		
		boolean verified = service.verify(getHeader(), getSignableContent(), getSignature());
		
		if (verified)
			state = State.VERIFIED;
			
		return verified;
	}
	
	
	/**
	 * Verifies the signature of this JSON Web Token (JWT) using the
	 * specified HMAC shared secret. The JWT must be in a 
	 * {@link State#SIGNED signed} state and its algorithm header one of the
	 * following:
	 *
	 * <ul>
	 *     <li>{@link JWA#HS256} (mandatory for JWS implementations)
	 *     <li>{@link JWA#HS384} 
	 *     <li>{@link JWA#HS512}
	 * </ul>
	 *
	 * @param sharedSecret The HMAC shared secret. Must not be {@code null}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public boolean hmacVerify(final byte[] sharedSecret)
		throws JWSException {
		
		ensureSignedOrVerifiedState();
		
		boolean verified = JWS.hmacVerify(getHeader(), getSignableContent(), getSignature(), sharedSecret);
		
		if (verified)
			state = State.VERIFIED;
			
		return verified;
	}
	
	
	/**
	 * Verifies the signature of this JSON Web Token (JWT) using the
	 * specified public RSA key. The JWT must be in a 
	 * {@link State#SIGNED signed} state and its algorithm header one of the
	 * following:
	 *
	 * <ul>
	 *     <li>{@link JWA#RS256} (recommended for JWS implementations)
	 *     <li>{@link JWA#RS384}
	 *     <li>{@link JWA#RS512}
	 * </ul>
	 *
	 *  @param publicKey The public RSA key to verify the signature. Must 
	 *                   not be {@code null}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public boolean rsaVerify(final RSAPublicKey publicKey)
		throws JWSException {
		
		ensureSignedOrVerifiedState();
		
		boolean verified = JWS.rsaVerify(getHeader(), getSignableContent(), getSignature(), publicKey);
		
		if (verified)
			state = State.VERIFIED;
			
		return verified;
	}
	
	
	/**
	 * Verifies the signature of this JSON Web Token (JWT) using the
	 * specified elliptic curve parameters. The JWT must be in a 
	 * {@link State#SIGNED signed} state and its algorithm header one of the
	 * following:
	 *
	 * <ul>
	 *     <li>{@link JWA#ES256} (recommended for JWS implementations)
	 *     <li>{@link JWA#ES384}
	 *     <li>{@link JWA#ES512}
	 * </ul>
	 *
	 * @param x The x elliptic curve parameter. Must not be {@code null}.
	 * @param y The y elliptic curve parameter. Must not be {@code null}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public boolean ecdsaVerify(final BigInteger x, final BigInteger y)
		throws JWSException {
		
		ensureSignedOrVerifiedState();
		
		boolean verified = JWS.ecdsaVerify(getHeader(), getSignableContent(), getSignature(), x, y);
		
		if (verified)
			state = State.VERIFIED;
			
		return verified;
	}
	
	
	/**
	 * Serialises this signed JSON Web Token (JWT) to its canonical format.
	 * It must be in a {@link State#SIGNED signed} or {@link State#VERIFIED
	 * verified} state.
	 *
	 * <pre>
	 * [header-base64url].[claimsSet-base64url].[signature-base64url]
	 * </pre>
	 *
	 * @return The serialised signed JWT.
	 *
	 * @throws IllegalStateException If the JWT is not in a 
	 *                               {@link State#SIGNED signed} or
	 *                               {@link State#VERIFIED verified state}.
	 */
	public String serialize() {
	
		if (state != State.SIGNED && state != State.VERIFIED)
			throw new IllegalStateException("The JWT must be in a signed or verified state");
		
		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');
		sb.append(claimsSet.toBase64URL().toString());
		sb.append('.');
		sb.append(signature.toString());
		return sb.toString();
	}
	
	
	/**
	 * Parses a signed JSON Web Token (JWT). The state of the parsed JWT 
	 * will be {@link State#SIGNED}.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The parsed signed JWT.
	 *
	 * @throws JWTException If the string couldn't be parsed to a valid or
	 *                      supported JWT.
	 */
	public static SignedJWT parse(String s)
		throws JWTException {
	
		Base64URL[] parts = JWT.split(s);
		
		if (parts.length != 3)
			throw new JWTException("Unexpected number of Base64URL parts, must be four");
		
		return new SignedJWT(parts[0], parts[1], parts[2]);
	}
}
