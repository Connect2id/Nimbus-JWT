/*
 * Copyright (c) 2011, Axel Nennker - http://axel.nennker.de/
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names xmldap, xmldap.org, xmldap.com nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.nimbusds.jwt;


import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Routines for JSON Web Encryption (JWE).
 *
 * <p>This class is still a work in progress.
 *
 * <p>To do:
 * 
 * <ul>
 *     <li>Add HMAC integrity protection for all non-authenticating encryption 
 *         algorithms.
 *     <li>Add support for missing ECDH-ES, A128KW, A256KW and A512KW algorithms
 *         listed in the JWA spec.
 * </ul>
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-01">JWE draft 01</a>.
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-04-03)
 */
public class JWE {


	/**
	 * The cryptographic parts of a JWE. This class is a simple wrapper to
	 * return the cipher text, the encrypted key and the integrity value 
	 * from encryption.
	 */
	public final static class Parts {
	
		
		/**
		 * The encrypted key (optional).
		 */
		final Base64URL encryptedKey;
		
		
		/**
		 * The cipher text.
		 */
		final Base64URL cipherText;
		
		
		/**
		 * The integrity value (optional).
		 */
		final Base64URL integrityValue;
		
		
		/**
		 * Creates a new cryptograhic JWE parts instance.
		 *
		 * @param encryptedKey   The encrypted key. {@code null} if not
		 *                       required by the encryption algorithm.
		 * @param cipherText     The cipher text. Must not be 
		 *                       {@code null}.
		 * @param integrityValue The integrity value according to
		 *                       {@link JWEHeader#getIntegrityAlgorithm},
		 *                       {@code null} if the JWE algorithm 
		 *                       provides built-in integrity check, else
		 *                       {@code null}.
		 */
		public Parts(final Base64URL encryptedKey, 
		             final Base64URL cipherText, 
			     final Base64URL integrityValue) {
	
			this.encryptedKey = encryptedKey;
			this.cipherText = cipherText;
			this.integrityValue = integrityValue;
		}
		
		
		/**
		 * Gets the encrypted key.
		 *
		 * @return The encrypted key, {@code null} if not required by 
		 *         the JWE algorithm.
		 */
		public Base64URL getEncryptedKey() {
		
			return encryptedKey;
		}
		
		
		/**
		 * Gets the cipher text.
		 *
		 * @return The cipher text.
		 */
		public Base64URL getCipherText() {
		
			return cipherText;
		}
		
		
		/**
		 * Gets the integrity value.
		 *
		 * @return The integrity value, {@code null} if the encryption
		 *         algorithm provides built-in integrity checking.
		 */
		 public Base64URL getIntegrityValue() {
		 
		 	return integrityValue;
		}
	}
	
	
	/**
	 * Performs {@link JWA#RSA1_5} or {@link JWA#RSA_OAEP} encryption with
	 * the specified public RSA key. The clear text will be compressed if 
	 * the {@link JWEHeader#getCompressionAlgorithm compression algorithm}
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
	 * @param header       The JWE header. Must not be {@code null}.
	 * @param clearText    The clear text to encrypt. Must not be 
	 *                     {@code null}.
	 * @param rsaPublicKey The public RSA key. Must not be {@code null}.
	 *
	 * @return The encrypted parts.
	 *
	 * @throws JWEException If encryption failed.
	 */
	public static Parts rsaEncrypt(final ReadOnlyJWEHeader header, 
	                               final byte[] clearText, 
				       final RSAPublicKey rsaPublicKey) 
		throws JWEException {
		
		int keylength;
		
		switch (header.getEncryptionMethod()) {

			case A128CBC:
			case A128GCM:
				keylength = 128;
				break;
				
			case A192CBC:
			case A192GCM:
				keylength = 192;
				break;
				
			case A256CBC:
			case A256GCM:
				keylength = 256;
				break;
				
			case A512CBC:
			case A512GCM:
				keylength = 512;
				break;
				
			default:
				throw new JWEException("Unsupported encryption algorithm, must be A128CBC, A128GCM, A192CBC, A256CBC, A256GCM or A512CBC");
		}
		
		Base64URL encryptedKey = null;
		Base64URL cipherText = null;
		
		try {
			SecretKey contentEncryptionKey = CryptoUtils.genAesKey(keylength);			

			switch (header.getAlgorithm()) {

				case RSA1_5:
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
					encryptedKey = Base64URL.encode(cipher.doFinal(contentEncryptionKey.getEncoded()));
					break;

				case RSA_OAEP:
					encryptedKey = Base64URL.encode(CryptoUtils.rsaoaepEncrypt(contentEncryptionKey.getEncoded(), rsaPublicKey));
					break;

				default:
					throw new JWEException("Unsupported algorithm, must be RSA1_5 or RSA_OAEP");
			}
			
			byte[] preparedClearText = CompressionUtils.compressIfRequired(header, clearText);

			switch (header.getEncryptionMethod()) {

				case A128CBC:
				case A192CBC:
				case A256CBC:
				case A512CBC:

					SafeObject keyBytes = new SafeObject();
					byte[] secretKeyBytes = contentEncryptionKey.getEncoded();
					keyBytes.set(secretKeyBytes);
					cipherText = Base64URL.encode(CryptoUtils.aescbcEncrypt(preparedClearText, keyBytes));
					break;

				case A128GCM:
				case A192GCM:
				case A256GCM:
				case A512GCM:
					Base64URL iv = header.getInitializationVector();
					
					if (iv == null)
						throw new JWEException("Missing initialization vector \"iv\" header");
					
					byte[] ivBytes = iv.decode();

					IvParameterSpec ivParamSpec = new IvParameterSpec(ivBytes);
					cipherText = Base64URL.encode(CryptoUtils.aesgcmEncrypt(ivParamSpec, contentEncryptionKey, preparedClearText));
					break;

				default: 
					throw new JWEException("Unsupported encryption algorithm, must be A128CBC, A128GCM, A192CBC, A256CBC, A256GCM or A512CBC");
			}
		
		} catch (Exception e) {
		
			if (e instanceof JWEException)
				throw (JWEException)e;
		
			throw new JWEException("Couldn't encrypt: " + e.getMessage(), e);
		}
		
		return new Parts(encryptedKey, cipherText, null);
	}
	
	
	/**
	 * Performs {@link JWA#RSA1_5} or {@link JWA#RSA_OAEP} decryption with
	 * the specified public RSA key. The clear text will be decompressed if 
	 * the {@link JWEHeader#getCompressionAlgorithm compression algorithm}
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
	 * @param header        The JWE header. Must not be {@code null}.
	 * @param encryptedKey  The encrypted key. Must not be {@code null}.
	 * @param cipherText    The cipher text to decrypt. Must not be 
	 *                      {@code null}.
	 * @param rsaPrivateKey The private RSA key. Must not be {@code null}.
	 *
	 * @return The clear text.
	 *
	 * @throws JWEException If decryption failed.
	 */
	public static byte[] rsaDecrypt(final ReadOnlyJWEHeader header,
					final Base64URL encryptedKey,
	                                final Base64URL cipherText, 
					final RSAPrivateKey rsaPrivateKey) 
		throws JWEException {

		int keylength;
		
		switch (header.getEncryptionMethod()) {
		
			case A128CBC:
			case A128GCM:
				keylength = 128;
				break;
				
			case A192CBC:
			case A192GCM:
				keylength = 192;
				break;
				
			case A256CBC:
			case A256GCM:
				keylength = 256;
				break;
				
			case A512CBC:
			case A512GCM:
				keylength = 512;
				break;
				
			default:
				throw new JWEException("Unsupported encryption algorithm, must be A128CBC, A128GCM, A192CBC, A256CBC, A256GCM or A512CBC");
		}
		
		try {
			SecretKeySpec keySpec;

			final String symmetricAlgorithm = "AES";

			switch (header.getAlgorithm()) {

				case RSA1_5:
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
					byte[] secretKeyBytes1 = cipher.doFinal(encryptedKey.decode());

					if (8* secretKeyBytes1.length != keylength) {
						throw new Exception("WebToken.decrypt RSA PKCS1Padding symmetric key length mismatch: " + secretKeyBytes1.length + " != " +  keylength);
					}

					keySpec = new SecretKeySpec(secretKeyBytes1, symmetricAlgorithm);

					break;

				case RSA_OAEP:

					byte[] secretKeyBytes2 = CryptoUtils.rsaoaepDecrypt(encryptedKey.decode(), rsaPrivateKey);

					if (8* secretKeyBytes2.length != keylength) {
						throw new Exception("WebToken.decrypt RSA OAEP symmetric key length mismatch: " + secretKeyBytes2.length + " != " +  keylength);
					}
					
					keySpec = new SecretKeySpec(secretKeyBytes2, symmetricAlgorithm);

					break;

				default:
					throw new JWEException("Unsupported algorithm, must be RSA1_5 or RSA_OAEP");
			}

			byte[] clearText = null;

			switch (header.getEncryptionMethod()) {

				case A128CBC:
				case A192CBC:
				case A256CBC:
				case A512CBC:
					SafeObject keyBytes = new SafeObject();
					byte[] secretKeyBytes = keySpec.getEncoded();
					keyBytes.set(secretKeyBytes);
					clearText = CryptoUtils.aescbcDecrypt(cipherText.decode(), keyBytes);
					break;
				case A128GCM:
				case A192GCM:
				case A256GCM:
				case A512GCM:
					Base64URL iv = header.getInitializationVector();
					
					if (iv == null)
						throw new JWEException("Missing initialization vector \"iv\" header");
					
					byte[] ivBytes = iv.decode();
					IvParameterSpec ivParamSpec = new IvParameterSpec(ivBytes);
					clearText = CryptoUtils.aesgcmDecrypt(ivParamSpec, keySpec, cipherText.decode());
					break;
				default:
					throw new JWEException("Unsupported encryption algorithm, must be A128CBC, A128GCM, A192CBC, A256CBC, A256GCM or A512CBC");
			}
			
			return CompressionUtils.decompressIfRequired(header, clearText);
			
		} catch (Exception e) {
		
			if (e instanceof JWEException)
				throw (JWEException)e;
		
			throw new JWEException("Couldn't decrypt: " + e.getMessage(), e);
		} 
	}
	
	
	/**
	 * Performs AES or AES-GCM encryption with the specified secret key. The 
	 * clear text will be compressed if the 
	 * {@link JWEHeader#getCompressionAlgorithm compression algorithm} is set
	 * to {@link CompressionAlgorithm#GZIP GZIP}.
	 *
	 * <p>Supported header algorithms:
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
	 * @param header    The JWE header. Must not be {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 * @param key       The secret key. Must not be {@code null}.
	 *
	 * @return The encrypted parts.
	 *
	 * @throws JWEException If encryption failed.
	 */
	public static Parts aesEncrypt(final ReadOnlyJWEHeader header,
	                               final byte[] clearText,
				       final SecretKey key) 
		throws JWEException {

		Base64URL cipherText = null;

		try {
			byte[] preparedClearText = CompressionUtils.compressIfRequired(header, clearText);
		
			switch (header.getAlgorithm()) {

				case AE128:
				case AE192:
				case AE256:
					SafeObject keyBytes = new SafeObject();
					byte[] secretKey = key.getEncoded();
					keyBytes.set(secretKey);
					cipherText = Base64URL.encode(CryptoUtils.aescbcEncrypt(preparedClearText, keyBytes));
					break;
				case A128GCM:
				case A192GCM:
				case A256GCM:
				case A512GCM:
					Base64URL ivBase64URL = header.getInitializationVector();
					
					if (ivBase64URL == null)
						throw new JWEException("JWE header missing initialization vector \"iv\"");
					
					byte[] iv = ivBase64URL.decode();
					
					IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
					cipherText = Base64URL.encode(CryptoUtils.aesgcmEncrypt(ivParamSpec, key, preparedClearText));
					break;
				default:
					throw new JWEException("Unsupported AES algorithm, must be AE128, AE192, AE256, A128CGM or A256GCM");
			}
			
		} catch (Exception e) {
		
			if (e instanceof JWEException)
				throw (JWEException)e;
		
			throw new JWEException("Couldn't encrypt: " + e.getMessage(), e);
		}
		
		return new Parts(null, cipherText, null);
	}
	
	
	/**
	 * Performs AES or AES-GCM decryption with the specified secret key. The 
	 * clear text will be decompressed if the 
	 * {@link JWEHeader#getCompressionAlgorithm compression algorithm}
	 * is set to {@link CompressionAlgorithm#GZIP GZIP}.
	 *
	 * <p>Supported header algorithms:
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
	 * @param header     The JWE header. Must not be {@code null}.
	 * @param cipherText The cipher text to decrypt. Must not be 
	 *                   {@code null}.
	 * @param key        The secret key. Must not be {@code null}.
	 *
	 * @return The clear text.
	 *
	 * @throws JWEException If decryption failed.
	 */
	public static byte[] aesDecrypt(final ReadOnlyJWEHeader header,
	                                final Base64URL cipherText, 
					final SecretKey key)
		throws JWEException {

		String secretKeyAlg = key.getAlgorithm();

		if (! secretKeyAlg.equals("AES"))
			throw new JWEException("Unsupported secret key AES algorithm: " + secretKeyAlg);
		
		
		try {
			byte[] clearText = null;
		
			switch (header.getAlgorithm()) {

				case AE128:
				case AE192:
				case AE256:
					SafeObject keyBytes = new SafeObject();
					byte[] secretKey = key.getEncoded();
					keyBytes.set(secretKey);
					clearText = CryptoUtils.aescbcDecrypt(cipherText.decode(), keyBytes);
					break;
				case A128GCM:
				case A192GCM:
				case A256GCM:
				case A512GCM:
					Base64URL ivBase64URL = header.getInitializationVector();
					
					if (ivBase64URL == null)
						throw new JWEException("JWE header missing initialization vector \"iv\"");
					
					byte[] iv = ivBase64URL.decode();
					
					IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
					clearText = CryptoUtils.aesgcmDecrypt(ivParamSpec, key, cipherText.decode());
					break;
				default:
					throw new JWEException("Unsupported AES algorithm, must be AE128, AE192, AE256, A128CGM or A256GCM");
			}
			
			return CompressionUtils.decompressIfRequired(header, clearText);
			
		} catch (Exception e) {

			if (e instanceof JWEException)
				throw (JWEException)e;
				
			throw new JWEException("Couldn't decrypt: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Prevents instantiation.
	 */
	private JWE() {
	
		// Nothing to do
	}
}
