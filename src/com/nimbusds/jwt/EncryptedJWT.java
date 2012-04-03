package com.nimbusds.jwt;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;


/**
 * Encrypted JSON Web Token (JWT).
 *
 * <p>The actual encryption and decryption is provided by the {@link JWE} class.
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>.
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-01">JWE draft 01</a>.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-04-02)
 */
public class EncryptedJWT extends JWT {


	/**
	 * Enumeration of the states of an encrypted JSON Web Token (JWT).
	 */
	public static enum State {
	
		
		/**
		 * The JWT is not encrypted yet.
		 */
		UNENCRYPTED,
		
		
		/**
		 * The JWT is encrypted.
		 */
		ENCRYPTED,
		
		
		/**
		 * The JWT is decrypted.
		 */
		DECRYPTED;
	}
	
	
	/**
	 * The header.
	 */
	private JWEHeader header;
	
	
	/** 
	 * The encrypted key, {@code null} if not applicable or available.
	 */
	private Base64URL encryptedKey;
	
	
	/**
	 * The cipher text, {@code null} if not available.
	 */
	private Base64URL cipherText;
	
	
	/**
	 * The integrity value, {@code null} if not available.
	 */
	private Base64URL integrityValue;
	
	
	/**
	 * The state.
	 */
	private State state;
	
	
	/**
	 * Creates a new unencrypted JSON Web Token (JWT) with the specified 
	 * header and claims set. The initial state will be 
	 * {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @param header    The JWE header. Must not be {@code null}.
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public EncryptedJWT(final JWEHeader header, final ClaimsSet claimsSet) {
	
		if (header == null)
			throw new NullPointerException("The JWE header must not be null");
			
		this.header = header;
		
		if (claimsSet == null)
			throw new NullPointerException("The claims set must not be null");
		
		this.claimsSet = claimsSet;
		
		encryptedKey = null;
		
		cipherText = null;
		
		state = State.UNENCRYPTED;
	}
	
	
	/**
	 * Creates a new encrypted JSON Web Token (JWT) with the specified 
	 * serialised parts. The state will be {@link State#ENCRYPTED 
	 * encrypted}.
	 *
	 * @param firstPart  The first part, corresponding to the JWE header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the encrypted 
	 *                   key. Empty or {@code null} if none.
	 * @param thirdPart  The third part, corresponding to the cipher text.
	 *                   Must not be {@code null}.
	 * @param fourthPart The fourth part, corresponding to the integrity
	 *                   value. Empty of {@code null} if none.
	 *
	 * @throws JWTException If parsing of the serialised parts failed.
	 */
	public EncryptedJWT(final Base64URL firstPart, 
	                    final Base64URL secondPart, 
			    final Base64URL thirdPart,
			    final Base64URL fourthPart)
		throws JWTException {
	
		if (firstPart == null)
			throw new NullPointerException("The first part must not be null");
		
		try {
			this.header = JWEHeader.parse(firstPart);
			
		} catch (HeaderException e) {
		
			throw new JWTException("Invalid or unsupported JWE header: " + e.getMessage(), e);
		}
		
		if (secondPart == null || secondPart.toString().isEmpty())
			encryptedKey = null;
		else
			encryptedKey = secondPart;
	
		if (thirdPart == null)
			throw new NullPointerException("The third part must not be null");
		
		cipherText = thirdPart;
		
		if (fourthPart == null || fourthPart.toString().isEmpty())
			integrityValue = null;
		else
			integrityValue = fourthPart;
		state = State.ENCRYPTED; // but not decrypted yet!
	}
	
	
	/**
	 * Gets the header of this encrypted JSON Web Token (JWT).
	 *
	 * @return The header.
	 */
	public ReadOnlyJWEHeader getHeader() {
	
		return header;
	}
	
	
	/**
	 * Gets the encrypted key of this encrypted JSON Web Token (JWT).
	 *
	 * @return The encrypted key, {@code null} not applicable or the token
	 *         has not been encrypted yet.
	 */
	public Base64URL getEncryptedKey() {
	
		return encryptedKey;
	}
	
	
	/**
	 * Gets the cipher of this encrypted JSON Web Token (JWT).
	 *
	 * @return The cipher text, {@code null} if the token has not been
	 *         encrypted yet.
	 */
	public Base64URL getCipherText() {
	
		return cipherText;
	}
	
	
	/**
	 * Gets the integrity value of this encrypted JSON Web Token (JWT).
	 *
	 * @return The integrity value, {@code null} if not applicable or the 
	 *         token has not been encrypted yet.
	 */
	public Base64URL getIntegrityValue() {
	
		return integrityValue;
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
	 * Ensures the current state is {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @throws IllegalStateException If the current state is not 
	 *                               unencrypted.
	 */
	private void ensureUnencryptedState() {
	
		if (state != State.UNENCRYPTED)
			throw new IllegalStateException("The JWT must be in an unencrypted state");
	}
	
	
	/**
	 * Ensures the current state is {@link State#ENCRYPTED unencrypted}.
	 *
	 * @throws IllegalStateException If the current state is not encrypted.
	 */
	private void ensureEncryptedState() {
	
		if (state != State.UNENCRYPTED)
			throw new IllegalStateException("The JWT must be in an encrypted state");
	}
	
	
	/**
	 * Encrypts this JSON Web Token (JWT) using the specified JWE service. 
	 * The JWT must be in a {@link State#UNENCRYPTED unencrypted} state.
	 *
	 * @param service The JWE service to use to encrypt this JWT. Must not 
	 *                be {@code null}.
	 *
	 * @throws JWEException If the JWT couldn't be encrypted.
	 */
	public void encrypt(final JWEService service)
		throws JWEException {
	
		if (service == null)
			throw new NullPointerException("The JWE service must not be null");
	
		ensureUnencryptedState();
		
		JWE.Parts parts = service.encrypt(getHeader(), claimsSet.toBytes());
		
		encryptedKey = parts.getEncryptedKey();
		cipherText = parts.getCipherText();
		integrityValue = parts.getIntegrityValue();
		
		state = State.ENCRYPTED;
	}
	
	
	/**
	 * Encrypts this JSON Web Token (JWT) using the specified public RSA 
	 * key. The JWT must be in a {@link State#UNENCRYPTED unencrypted} 
	 * state. The clear text will be compressed if the 
	 * {@link JWEHeader#getCompressionAlgorithm compression algorithm}
	 * is set to {@link CompressionAlgorithm#GZIP GZIP}.
	 *
	 * <p>Supported algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A128CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A192CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A256CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A512CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A128GCM} and 
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A192GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A256GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A512GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A128CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A192CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A256CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A512CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A128GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A192GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A256GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A512GCM} and  
	 *         Initialisation Vector (IV)
	 * </ul>
	 *
	 * @param rsaPublicKey The public RSA key. Must not be {@code null}.
	 *
	 * @throws JWEException If encryption failed.
	 */
	public void rsaEncrypt(final RSAPublicKey rsaPublicKey)
		throws JWEException {
		
		ensureUnencryptedState();
		
		JWE.Parts parts = JWE.rsaEncrypt(getHeader(), claimsSet.toBytes(), rsaPublicKey);
		
		encryptedKey = parts.getEncryptedKey();
		cipherText = parts.getCipherText();
		integrityValue = parts.getIntegrityValue();
		
		state = State.ENCRYPTED;
	}
	
	
	/**
	 * Encrypts this JSON Web Token (JWT) using the specified secret AES
	 * key. The JWT must be in a {@link State#UNENCRYPTED unencrypted} 
	 * state. The clear text will be compressed if the 
	 * {@link JWEHeader#getCompressionAlgorithm compression algorithm}
	 * is set to {@link CompressionAlgorithm#GZIP GZIP}.
	 *
	 * <p>Supported algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#AE128}
	 *     <li>{@link JWA#AE192}
	 *     <li>{@link JWA#AE256}
	 *     <li>{@link JWA#A128GCM} (recommended for JWE implementations)
	 *     <li>{@link JWA#A192GCM}
	 *     <li>{@link JWA#A256GCM} (recommended for JWE implementations)
	 *     <li>{@link JWA#A512GCM}
	 * </ul>
	 *
	 * @param key The secret key. Must not be {@code null}.
	 *
	 * @throws JWEException If encryption failed.
	 */
	public void aesEncrypt(final SecretKey key)
		throws JWEException {
		
		ensureUnencryptedState();
		
		JWE.Parts parts = JWE.aesEncrypt(getHeader(), claimsSet.toBytes(), key);
		
		encryptedKey = parts.getEncryptedKey();
		cipherText = parts.getCipherText();
		integrityValue = parts.getIntegrityValue();
		
		state = State.ENCRYPTED;
	}
	
	
	/**
	 * Decrypts this JSON Web Token (JWT) using the specified JWE service. 
	 * The JWT must be in a {@link State#ENCRYPTED encrypted} state.
	 *
	 * @param service The JWE service to use to decrypt this JWT. Must not 
	 *                be {@code null}.
	 *
	 * @throws JWEException If the JWT couldn't be decrypted.
	 */
	public void decrypt(final JWEService service)
		throws JWEException {
		
		if (service == null)
			throw new NullPointerException("The JWE service must not be null");
	
		ensureEncryptedState();
		
		claimsSet = new ClaimsSet(service.decrypt(getHeader(), getEncryptedKey(), getCipherText(), getIntegrityValue()));
		
		state = State.DECRYPTED;
	}
	
	
	/**
	 * Decrypts this JSON Web Token (JWT) using the specified private RSA
	 * key. The JWT must be in a {@link State#ENCRYPTED encrypted} state.
	 * The clear text will be decompressed if the 
	 * {@link JWEHeader#getCompressionAlgorithm compression algorithm}
	 * is set to {@link CompressionAlgorithm#GZIP GZIP}.
	 *
	 * <p>Supported algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A128CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A192CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A256CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A512CBC}
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A128GCM} and 
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A192GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A256GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA1_5} with {@link JWA#A512GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A128CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A192CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A256CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A512CBC}
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A128GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A192GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A256GCM} and  
	 *         Initialisation Vector (IV)
	 *     <li>{@link JWA#RSA_OAEP} with {@link JWA#A512GCM} and  
	 *         Initialisation Vector (IV)
	 * </ul>
	 *
	 * @param rsaPrivateKey The private RSA key. Must not be {@code null}.
	 *
	 * @throws JWEException If decryption failed.
	 */
	public void rsaDecrypt(final RSAPrivateKey rsaPrivateKey)
		throws JWEException {
		
		ensureEncryptedState();
		
		claimsSet = new ClaimsSet(JWE.rsaDecrypt(getHeader(), getEncryptedKey(), getCipherText(), rsaPrivateKey));
		
		state = State.DECRYPTED;
	}
	
	
	/**
	 * Decrypts this JSON Web Token (JWT) using the specified secret AES
	 * key. The JWT must be in a {@link State#ENCRYPTED encrypted} state.
	 * The clear text will be decompressed if the 
	 * {@link JWEHeader#getCompressionAlgorithm compression algorithm}
	 * is set to {@link CompressionAlgorithm#GZIP GZIP}.
	 *
	 * <p>Supported algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#AE128}
	 *     <li>{@link JWA#AE192}
	 *     <li>{@link JWA#AE256}
	 *     <li>{@link JWA#A128GCM} (recommended for JWE implementations)
	 *     <li>{@link JWA#A192GCM}
	 *     <li>{@link JWA#A256GCM} (recommended for JWE implementations)
	 *     <li>{@link JWA#A512GCM}
	 * </ul>
	 *
	 * @param key The secret key. Must not be {@code null}.
	 *
	 * @throws JWEException If decryption failed.
	 */
	public void aesDecrypt(final SecretKey key)
		throws JWEException {
		
		ensureEncryptedState();
		
		claimsSet = new ClaimsSet(JWE.aesDecrypt(getHeader(), getCipherText(), key));
		
		state = State.DECRYPTED;
	}
	
	
	/**
	 * Serialises this encrypted JSON Web Token (JWT) to its canonical 
	 * format. It must be in a {@link State#ENCRYPTED signed} or 
	 * {@link State#DECRYPTED decrypted} state.
	 *
	 * <pre>
	 * [header-base64url].[encryptedKey-base64url].[cipherText-base64url]
	 * </pre>
	 *
	 * @return The serialised encrypted JWT.
	 */
	public String serialize() {
	
		if (state != State.ENCRYPTED || state != State.DECRYPTED)
			throw new IllegalStateException("The JWT must be in an encrypted or decrypted state");
		
		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');
		
		if (encryptedKey != null)
			sb.append(encryptedKey.toString());
		
		sb.append('.');
		sb.append(cipherText.toString());
		return sb.toString();
	}
	
	
	/**
	 * Parses an encrypted JSON Web Token (JWT). The state of the parsed JWT 
	 * will be {@link State#ENCRYPTED}.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The parsed encrypted JWT.
	 *
	 * @throws JWTException If the string couldn't be parsed to a valid or
	 *                      supported JWT.
	 */
	public static EncryptedJWT parse(String s)
		throws JWTException {
	
		Base64URL[] parts = JWT.split(s);
		
		if (parts.length != 4)
			throw new JWTException("Unexpected number of Base64URL parts, must be four");
		
		return new EncryptedJWT(parts[0], parts[1], parts[2], parts[4]);
	}
}
