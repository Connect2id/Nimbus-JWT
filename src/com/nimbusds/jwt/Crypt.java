/*
  Name:         net.sourceforge.lightcrypto.Crypt
  Licensing:    LGPL (lesser GNU Public License)
  API:          Bouncy Castle (http://www.bouncycastle.org) lightweight API

  Disclaimer:

  COVERED CODE IS PROVIDED UNDER THIS LICENSE ON AN "AS IS" BASIS, WITHOUT WARRANTY OF ANY KIND,
  EITHER EXPRESSED OR IMPLIED, INCLUDING, WITHOUT LIMITATION, WARRANTIES THAT THE COVERED CODE
  IS FREE OF DEFECTS, MERCHANTABLE, FIT FOR A PARTICULAR PURPOSE OR NON-INFRINGING. THE ENTIRE
  RISK AS TO THE QUALITY AND PERFORMANCE OF THE COVERED CODE IS WITH YOU. SHOULD ANY COVERED CODE
  PROVE DEFECTIVE IN ANY RESPECT, YOU (NOT THE INITIAL DEVELOPER OR ANY OTHER CONTRIBUTOR)
  ASSUME THE COST OF ANY NECESSARY SERVICING, REPAIR OR CORRECTION. THIS DISCLAIMER OF WARRANTY
  CONSTITUTES AN ESSENTIAL PART OF THIS LICENSE. NO USE OF ANY COVERED CODE IS AUTHORIZED
  HEREUNDER EXCEPT UNDER THIS DISCLAIMER.

  (C) Copyright 2003 Gert Van Ham

*/
package com.nimbusds.jwt;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * Encryption and decryption routines based on the BouncyCastle lightweight API.
 *
 * @author Gert Van Ham
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-31)
 */
class Crypt {

	
	/**
	 * Default byte buffer size.
	 */
	private static int BUFFERSIZE_BYTES = 64;
	
	
	/**
	 * Default file buffer size.
	 */
	private static int BUFFERSIZE_FILE = 8192;
	

	/**
	 * Encrypts the specified clear text with a symmetric key (AES light 
	 * engine, CBC mode, PKCS7 padding).
	 *
	 * @param clearText The clear text to encrypt. Must not be 
	 *                  {@code null}.
	 * @param key       The symmetric key. Must not be {@code null}.
	 *
	 * @return The cipher text.
	 *
	 * @throws CryptoException If an encryption exception is encountered.
	 * @throws IOException     If an I/O exception is encountered.
	 */
	public static byte[] encrypt(final byte[] clearText, final SafeObject key)
		throws CryptoException, IOException {

		return encrypt(clearText, key, null);
	}


	/**
         * Encrypts the specified clear text with a symmetric key (AES light 
	 * engine, CBC mode, PKCS7 padding).
	 *
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 * @param key       The symmetric key. Must not be {@code null}.
	 * @param seed      The seed for SecureRandom. May be {@code null}.
	 *
	 * @return The cipher text.
	 *
	 * @throws CryptoException If an encryption exception is encountered.
	 * @throws IOException     If an I/O exception is encountered.
	 */
	public static byte[] encrypt(final byte[] clearText, final SafeObject key, final byte[] seed)
		throws CryptoException, IOException {

		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DataOutputStream dao = new DataOutputStream(bao);
		
		encrypt(new ByteArrayInputStream(clearText), dao, key, seed, BUFFERSIZE_BYTES);
		
        	byte[] result = bao.toByteArray();

		dao.flush();
		dao.close();

		return result;
	}
	
	
	/**
         * Encrypts the specified clear text input stream with a symmetric key 
	 * (AES light engine, CBC mode, PKCS7 padding). The cipher text is 
	 * stored into the provided data output stream.
	 *
	 * @param is           The clear text input stream to encrypt. Must not
	 *                     be {@code null}.
	 * @param daos         The output stream for the cipher text. Must not
	 *                     be {@code null}.
	 * @param key          The symmetric key. Must not be {@code null}.
	 * @param seed         The seed for SecureRandom. May be {@code null}.
	 * @param bufferlength The buffer length in bytes.
	 *
	 * @throws CryptoException If encryption failed.
	 */
	public static void encrypt(final InputStream is, final DataOutputStream daos, 
	                           final SafeObject key, final byte[] seed, 
				   final int bufferlength)
		throws CryptoException {

        	KeyParameter keyParam = null;

		try {
			SecureRandom sr = new SecureRandom();

			// Set seed if available
			if (seed != null && seed.length > 0)
				sr.setSeed(seed);
			
			// Initialize the AES cipher ("light" engine) in CBC mode with PKCS7 padding
			AESLightEngine blockCipher = new AESLightEngine();
			CBCBlockCipher cbcCipher = new CBCBlockCipher(blockCipher);
			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcCipher);
			
			// Create an IV of random data.
			byte[] iv = new byte[blockCipher.getBlockSize()];
			sr.nextBytes(iv);

			// Use the key bytes to create a key
			keyParam = new KeyParameter(key.get());
			
			// Use the IV and key param to create cipherparameters
			ParametersWithIV ivparam = new ParametersWithIV(keyParam, iv);

			// Write the IV to the outputstream
			daos.write(iv, 0, iv.length);

			// Concatenate the IV and the message.
			byte[] buffer = new byte[bufferlength];
			int length = cipher.getOutputSize(bufferlength);
			byte[] result = new byte[length];
			int outputLen = 0;

			// Initialize the cipher for encrypting with the key param and IV
			cipher.init(true, ivparam);

			// Read bytes into buffer and feed these bytes into the cipher
			while ((length = is.read(buffer)) != -1) {
				
				outputLen = cipher.processBytes(buffer, 0, length, result, 0);

				if (outputLen > 0)
					daos.write(result, 0, outputLen);
			}

			// Do final for encrypting last bytes
			outputLen = cipher.doFinal(result, 0);

			if (outputLen > 0)
				daos.write(result, 0, outputLen);
				
		} catch (Exception e) {
		
			throw new CryptoException(e.getMessage(), e);
        
		} finally {

			// Clear sensitive information from memory
			keyParam = null;
			
			if (seed != null)
				Clean.blank(seed);
		}
	}
	
	
	/**
	 * Decrypts the specified cipher text with a symmetric key (AES light 
	 * engine, CBC mode, PKCS7 padding).
	 *
	 * @param cipherText The cipher text to decrypt. Must not be 
	 *                   {@code null}.
	 * @param key        The symmetric key. Must not be {@code null}.
	 * 
	 * @return The clear text.
	 *
	 * @throws CryptoException If an encryption exception is encountered.
	 * @throws IOException     If an I/O exception is encountered.
	 */
	public static byte[] decrypt(final byte[] cipherText, final SafeObject key)
		throws CryptoException, IOException {

		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DataOutputStream dao = new DataOutputStream(bao);

		// decrypt
		decrypt(new ByteArrayInputStream(cipherText), dao, key, BUFFERSIZE_BYTES);

		//close outputstream
		dao.flush();
		dao.close();

		return bao.toByteArray();
	}
    

	/**
	 * Decrypts the specifed cipher text input stream with a symmetric key 
	 * (AES light engine, CBC mode, PKCS7 padding). The clear text is stored
	 * into the provided data output stream.
	 *
	 * @param is           The cipher text input stream to decrypt. Must not 
	 *                     be {@code null}.
         * @param daos         The output stream for the clear text. Must not be
	 *                     {@code null}.
         * @param key          The symmetric key. Must not be {@code null}.
         * @param bufferlength The buffer length in bytes.
	 *
	 * @throws CryptoException for all encryption errors
	 */
	public static void decrypt(final InputStream is, final DataOutputStream daos,
	                           final SafeObject key, final int bufferlength)
		throws CryptoException {
		
		KeyParameter keyParam = null;

		try {
			// Use the key bytes to create a key param
			keyParam = new KeyParameter(key.get());

			AESLightEngine blockCipher = new AESLightEngine();
			CBCBlockCipher cbcCipher = new CBCBlockCipher(blockCipher);
			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcCipher);

			// Read the IV from the inputstream
			byte[] iv = new byte[blockCipher.getBlockSize()];
			is.read(iv);

			// Use the IV and key to create cipherparameters
			ParametersWithIV ivparam = new ParametersWithIV(keyParam, iv);

			byte[] buffer = new byte[bufferlength];
			int length = cipher.getOutputSize(buffer.length);
			byte[] result = new byte[length];
			int outputLen = 0;

			// Initialize the cipher for decrypting the key and IV
			cipher.init(false, ivparam);

			// Read bytes into buffer and feed these bytes into the cipher
			while ((length = is.read(buffer)) != -1) {

				outputLen = cipher.processBytes(buffer, 0, length, result, 0);

				if (outputLen > 0)
					daos.write(result, 0, outputLen);
			}
			
			// doFinal for encrypting last bytes
			outputLen = cipher.doFinal(result, 0);

			if (outputLen > 0)
				daos.write(result, 0, outputLen);
				
		} catch (Exception e) {
		
			throw new CryptoException(e.getMessage(), e);
			
		} finally {

			// Clear sensitive information from memory
			keyParam = null;
		}
	}
}

