package com.nimbusds.jwt;


import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * Cryptographic utilities.
 *
 * @author Charlie Mortimore
 * @author Vladimir Dzhuvinov
 * @version 1.8 (2012-04-01)
 */
class CryptoUtils {
	
	
	/**
	 * Encrypts the specified clear text using AES with a Chained Block 
	 * Cipher (CBC).
	 *
	 * @param clearText The clear text to encrypt, must not be {@code null}.
	 * @param key       The AES key, must not be {@code null}.
	 *
	 * @return The cipher text.
	 *
	 * @throws CryptoException If an encryption exception is encountered.
         */
	public static byte[] aescbcEncrypt(final byte[] clearText, final SafeObject key) 
		throws CryptoException {
		
		try {
			return Crypt.encrypt(clearText, key);
			
		} catch (CryptoException e) {
			
			throw new CryptoException(e.getMessage(), e);
			
		} catch (IOException e) {
			
			throw new CryptoException(e.getMessage(), e);
		}
	}


	/**
	 * Decrypts the specified cipher text using AES with a Chained Block 
	 * Cipher (CBC).
	 *
	 * @param cipherText The cipher text to decrypt, must not be 
	 *                   {@code null}.
	 * @param key        The AES key, must not be {@code null}.
	 *
	 * @return The clear text.
	 *
	 * @throws CryptoException If a decryption exception is encountered.
	 */
	public static byte[] aescbcDecrypt(final byte[] cipherText, final SafeObject key) 
		throws CryptoException {

		try {
			return Crypt.decrypt(cipherText, key);
			
		} catch (CryptoException e) {

			throw new CryptoException(e.getMessage(), e);
			
		} catch (IOException e) {

			throw new CryptoException(e.getMessage(), e);
		}
	}


	/**
	 * Encrypts the specified clear text using RSA with OAEP.
	 *
	 * @param clearText    The clear text to encrypt. Must not be 
	 *                     {@code null}.
	 * @param rsaPublicKey The public RSA key. Must not be {@code null}.
	 *
	 * @return The cipher text.
	 *
	 * @throws CryptoException If an encryption exception is encountered.
	 */
	public static byte[] rsaoaepEncrypt(final byte[] clearText, final RSAPublicKey rsaPublicKey)
		throws CryptoException {
		
		AsymmetricBlockCipher engine = new RSAEngine();
		OAEPEncoding cipher = new OAEPEncoding(engine);
		
		BigInteger mod = rsaPublicKey.getModulus();
		BigInteger exp = rsaPublicKey.getPublicExponent();
		RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
		cipher.init(true, keyParams);

		int inputBlockSize = cipher.getInputBlockSize();
		int outputBlockSize = cipher.getOutputBlockSize();
		
		try {
			return cipher.processBlock(clearText, 0, clearText.length);
			
		} catch (InvalidCipherTextException e) {

			throw new CryptoException(e.getMessage(), e);
		}
	}
	
	
	/**
         * Decrypts the specified cipher text using RSA with OAEP.
	 *
	 * @param cipherText The cipher text to decrypt. Must not be 
	 *                   {@code null}.
	 * @param inputKey   The private RSA key. Must not be {@code null}.
	 * 
	 * @return The clear text.
	 *
	 * @throws CryptoException If a decryption exception is encountered.
	 */
	public static byte[] rsaoaepDecrypt(final byte[] cipherText, final PrivateKey inputKey)
		throws CryptoException {

		RSAPrivateKey key =  (RSAPrivateKey) inputKey;
		RSAEngine engine = new RSAEngine();
		OAEPEncoding cipher = new OAEPEncoding(engine);
		BigInteger mod = key.getModulus();
		BigInteger exp = key.getPrivateExponent();
		RSAKeyParameters keyParams = new RSAKeyParameters(true, mod, exp);
		cipher.init(false, keyParams);

		try {
            		return cipher.processBlock(cipherText, 0, cipherText.length);

		} catch (InvalidCipherTextException e) {

			throw new CryptoException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Performs authenticated AES Galois/Counter Mode (AES-GCM) encryption.
	 *
	 * <p>See https://developer-content.emc.com/docs/rsashare/share_for_java/1.1/dev_guide/group__JCESAMPLES__ENCDEC__SYMCIPHER__AESGCM.html
	 *
	 * @param ivParamSpec The initialisation vector spec. Must not be 
	 *                    {@code null}.
	 * @param secretKey   The secret AES key. Must not be {@code null}.
	 * @param plainText   The plain text to encrypt. Must not be 
	 *                    {@code null}.
	 *
	 * @return The cipher text.
	 *
	 * @throws CryptoException If an encryption exception is encountered.
	 */
	protected static byte[] aesgcmEncrypt(final IvParameterSpec ivParamSpec, 
	                                      final SecretKey secretKey, 
					      final byte[] plainText) 
		throws CryptoException {

		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParamSpec);
			return cipher.doFinal(plainText);
			
		} catch (Exception e) {
		
			throw new CryptoException(e.getMessage(), e);
		}
	}


	/**
	 * Performs authenticated AES Galois/Counter Mode (AES-GCM) decryption.
	 *
	 * @param ivParamsSpec The initialisation vector spec. Must not be 
	 *                     {@code null}.
	 * @param secretKey    The secret AES key. Must not be {@code null}.
	 * @param cipherText   The cipher text to decrypt. Must not be 
	 *                     {@code null}.
	 *
	 * @return The clear text.
	 *
	 * @throws CryptoException If a decryption exception is encountered.
	 */  
	protected static byte[] aesgcmDecrypt(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText) 
		throws CryptoException {

		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParamSpec);
			return cipher.doFinal(cipherText);
			
		} catch (Exception e) {
		
			throw new CryptoException(e.getMessage(), e);
		}
	}
    
    
	/**
	 * Generates an AES SecretKey with the specified bit length.
	 *
	 * @param bitSize The desired bit length of the key.
	 *
	 * @return The encoded key as a byte array.
	 *
	 * @throws CryptoException If the key couldn't be generated.
	 */
	public static byte[] genKey(final int bitSize)
		throws CryptoException {

		SecretKey key = genAesKey(bitSize);
		return key.getEncoded();
	}
	
	
	/**
	 * Generates an AES SecretKey with the specified bit length.
	 *
	 * @param bitSize The desired bit length of the key.
	 *
	 * @return The secret key.
	 *
	 * @throws CryptoException If the key couldn't be generated.
	 */
	public static SecretKey genAesKey(final int bitSize)
		throws CryptoException {

		KeyGenerator keygen;

	        try {
			keygen = KeyGenerator.getInstance("AES");
			
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoException(e.getMessage(), e);
		}
		
		keygen.init(bitSize);
		return keygen.generateKey();
	}
}
