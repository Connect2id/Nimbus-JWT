package com.nimbusds.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;


/**
 * Tests the encryption utility class.
 *
 * @version 1.8 (2012-04-01)
 */
public class CryptoUtilsTest extends TestCase {

	
	public void testRsaoaep() {
	
		String clearText = "test";

		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024, new SecureRandom());
			
			KeyPair kp = keyGen.generateKeyPair();
			RSAPublicKey rsaPublicKey = (RSAPublicKey)kp.getPublic();
			byte[] cipherText = CryptoUtils.rsaoaepEncrypt(clearText.getBytes("UTF-8"), rsaPublicKey);

			byte[] decrypted = CryptoUtils.rsaoaepDecrypt(cipherText, kp.getPrivate());
			assertEquals(clearText, new String(decrypted));
			
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}
	
	
	private void testAesGcm(final IvParameterSpec ivParamSpec, 
	                        final SecretKey secretKey, 
				final byte[] clearText) 
		throws CryptoException {

		byte[] cipherText = CryptoUtils.aesgcmEncrypt(ivParamSpec, secretKey, clearText);

		byte[] decryptedClearText = CryptoUtils.aesgcmDecrypt(ivParamSpec, secretKey, cipherText);

		String clearTextB64 = BASE64.encodeBytesNoBreaks(clearText);
		String decryptedClearTextB64 = BASE64.encodeBytesNoBreaks(decryptedClearText);
		assertEquals(clearTextB64, decryptedClearTextB64);
	}
	
	
	public void testAesGcm128() 
		throws CryptoException {

		byte[] clearText = "plaintext".getBytes();
		byte[] keyData = BASE64.decode("wkp7v4KkBox9rSwVBXT+aA==");
		SecretKey secretKey = new SecretKeySpec(keyData, "AES128");

		byte[] N = Hex.decode("cafebabefacedbaddecaf888");
		IvParameterSpec ivParamSpec = new IvParameterSpec(N);

		testAesGcm(ivParamSpec, secretKey, clearText);
	}
}
