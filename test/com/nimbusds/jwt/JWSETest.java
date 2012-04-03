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


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import junit.framework.TestCase;


/**
 * JWS + JWE tests.
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-04-02)
 */
public class JWSETest extends TestCase {


	JSONObject joeO = null;

	String joeStr = "{\"iss\":\"joe\",\r\n" +
		" \"exp\":1300819380,\r\n" +
		" \"http://example.com/is_root\":true}";

	String hs256 = "{\"typ\":\"JWT\",\r\n"+
        	" \"alg\":\"HS256\"}";
		
	String hs384 = "{\"typ\":\"JWT\",\r\n"+
        	 " \"alg\":\"HS384\"}";
		 
	String hs512 = "{\"typ\":\"JWT\",\r\n"+
        	 " \"alg\":\"HS512\"}";
		 
	byte[] hsKey = {3, (byte)35, (byte)53, (byte)75, (byte)43, (byte)15, (byte)165, (byte)188, (byte)131, (byte)126, (byte)6, (byte)101, (byte)119, (byte)123, (byte)166, (byte)143, (byte)90, (byte)179, (byte)40, (byte)230, (byte)240, (byte)84, (byte)201, (byte)40, (byte)169, (byte)15, (byte)132, (byte)178, (byte)210, (byte)80, (byte)46, (byte)191, (byte)211, (byte)251, (byte)90, (byte)146, (byte)210, (byte)6, (byte)71, (byte)239, (byte)150, (byte)138, (byte)180, (byte)195, (byte)119, (byte)98, (byte)61, (byte)34, (byte)61, (byte)46, (byte)33, (byte)114, (byte)5, (byte)46, (byte)79, (byte)8, (byte)192, (byte)205, (byte)154, (byte)245, (byte)103, (byte)208, (byte)128, (byte)163};

	String es256 = "{\"alg\":\"ES256\"}";
	String es384 = "{\"alg\":\"ES384\"}";
	String es512 = "{\"alg\":\"ES512\"}";

	String rs256 = "{\"alg\":\"RS256\"}";
	String rs384 = "{\"alg\":\"RS384\"}";
	String rs512 = "{\"alg\":\"RS512\"}";

	String ae128 = "{\"alg\":\"AE128\"}";
	String ae192 = "{\"alg\":\"AE192\"}";
	String ae256 = "{\"alg\":\"AE256\"}";

	String A128GCM = "{\"alg\":\"A128GCM\"}";

	String re256GCM = "{\"alg\":\"RSA1_5\",\r\n"+
		"\"enc\":\"A256GCM\",\r\n"+
		"\"iv\":\"__79_Pv6-fg\",\r\n"+
		"\"x5t\":\"7noOPq-hJ1_hCnvWh6IeYI2w9Q0\"}";

	String re128GCM = "{\"alg\":\"RSA1_5\",\r\n"+
		"\"enc\":\"A128GCM\",\r\n"+
		"\"iv\":\"__79_Pv6-fg\",\r\n"+
		"\"x5t\":\"7noOPq-hJ1_hCnvWh6IeYI2w9Q0\"}";

	String ae128b64;
	String ae192b64;
	String ae256b64;

	String rsa15AesGcm128HeaderStr;
	String rsa15AesGcm128HeaderStrb64;

	String rsa15AesGcm256HeaderStr;
	String rsa15AesGcm256HeaderStrb64;

	String rsaOaepAesCbc128HeaderStr;
	String rsaOaepAesCbc128HeaderStrb64;

	String rsaOaepAesCbc192HeaderStr;
	String rsaOaepAesCbc192HeaderStrb64;

	String rsaOaepAesCbc256HeaderStr;
	String rsaOaepAesCbc256HeaderStrb64;

	RSAPublicKey rsaPublicKey;
	RSAPrivateKey rsaPrivKey;

	final String epbe = "{\"alg\":\"EPBE\",\r\n"+
        	" \"kid\":\"iauxBG<9\"}"; // the userid the password is bound to. This is NOT encrypted.
	String epbeb64;

	String keybytes128B64 = null;
	String keybytes256B64 = null;


	public void setUp() {
	
		try {
			super.setUp();

			final byte[] n = {(byte)161, (byte)248, (byte)22, (byte)10, (byte)226, (byte)227, (byte)201, (byte)180, (byte)101, (byte)206, (byte)141, (byte)45, (byte)101, (byte)98, (byte)99, (byte)54, (byte)43, (byte)146, (byte)125, (byte)190, (byte)41, (byte)225, (byte)240, (byte)36, (byte)119, (byte)252, (byte)22, (byte)37, (byte)204, (byte)144, (byte)161, (byte)54, (byte)227, (byte)139, (byte)217, (byte)52, (byte)151, (byte)197, (byte)182, (byte)234, (byte)99, (byte)221, (byte)119, (byte)17, (byte)230, (byte)124, (byte)116, (byte)41, (byte)249, (byte)86, (byte)176, (byte)251, (byte)138, (byte)143, (byte)8, (byte)154, (byte)220, (byte)75, (byte)105, (byte)137, (byte)60, (byte)193, (byte)51, (byte)63, (byte)83, (byte)237, (byte)208, (byte)25, (byte)184, (byte)119, (byte)132, (byte)37, (byte)47, (byte)236, (byte)145, (byte)79, (byte)228, (byte)133, (byte)119, (byte)105, (byte)89, (byte)75, (byte)234, (byte)66, (byte)128, (byte)211, (byte)44, (byte)15, (byte)85, (byte)191, (byte)98, (byte)148, (byte)79, (byte)19, (byte)3, (byte)150, (byte)188, (byte)110, (byte)155, (byte)223, (byte)110, (byte)189, (byte)210, (byte)189, (byte)163, (byte)103, (byte)142, (byte)236, (byte)160, (byte)198, (byte)104, (byte)247, (byte)1, (byte)179, (byte)141, (byte)191, (byte)251, (byte)56, (byte)200, (byte)52, (byte)44, (byte)226, (byte)254, (byte)109, (byte)39, (byte)250, (byte)222, (byte)74, (byte)90, (byte)72, (byte)116, (byte)151, (byte)157, (byte)212, (byte)185, (byte)207, (byte)154, (byte)222, (byte)196, (byte)199, (byte)91, (byte)5, (byte)133, (byte)44, (byte)44, (byte)15, (byte)94, (byte)248, (byte)165, (byte)193, (byte)117, (byte)3, (byte)146, (byte)249, (byte)68, (byte)232, (byte)237, (byte)100, (byte)193, (byte)16, (byte)198, (byte)182, (byte)71, (byte)96, (byte)154, (byte)164, (byte)120, (byte)58, (byte)235, (byte)156, (byte)108, (byte)154, (byte)215, (byte)85, (byte)49, (byte)48, (byte)80, (byte)99, (byte)139, (byte)131, (byte)102, (byte)92, (byte)111, (byte)111, (byte)122, (byte)130, (byte)163, (byte)150, (byte)112, (byte)42, (byte)31, (byte)100, (byte)27, (byte)130, (byte)211, (byte)235, (byte)242, (byte)57, (byte)34, (byte)25, (byte)73, (byte)31, (byte)182, (byte)134, (byte)135, (byte)44, (byte)87, (byte)22, (byte)245, (byte)10, (byte)248, (byte)53, (byte)141, (byte)154, (byte)139, (byte)157, (byte)23, (byte)195, (byte)64, (byte)114, (byte)143, (byte)127, (byte)135, (byte)216, (byte)154, (byte)24, (byte)216, (byte)252, (byte)171, (byte)103, (byte)173, (byte)132, (byte)89, (byte)12, (byte)46, (byte)207, (byte)117, (byte)147, (byte)57, (byte)54, (byte)60, (byte)7, (byte)3, (byte)77, (byte)111, (byte)96, (byte)111, (byte)158, (byte)33, (byte)224, (byte)84, (byte)86, (byte)202, (byte)229, (byte)233, (byte)161};
			final byte[] e = {1, 0, 1};
			final byte[] d = {18, (byte)174, (byte)113, (byte)164, (byte)105, (byte)205, (byte)10, (byte)43, (byte)195, (byte)126, (byte)82, (byte)108, (byte)69, (byte)0, (byte)87, (byte)31, (byte)29, (byte)97, (byte)117, (byte)29, (byte)100, (byte)233, (byte)73, (byte)112, (byte)123, (byte)98, (byte)89, (byte)15, (byte)157, (byte)11, (byte)165, (byte)124, (byte)150, (byte)60, (byte)64, (byte)30, (byte)63, (byte)207, (byte)47, (byte)44, (byte)211, (byte)189, (byte)236, (byte)136, (byte)229, (byte)3, (byte)191, (byte)198, (byte)67, (byte)155, (byte)11, (byte)40, (byte)200, (byte)47, (byte)125, (byte)55, (byte)151, (byte)103, (byte)31, (byte)82, (byte)19, (byte)238, (byte)216, (byte)193, (byte)90, (byte)37, (byte)216, (byte)213, (byte)206, (byte)160, (byte)2, (byte)94, (byte)227, (byte)171, (byte)46, (byte)139, (byte)127, (byte)121, (byte)33, (byte)111, (byte)198, (byte)59, (byte)234, (byte)86, (byte)39, (byte)83, (byte)180, (byte)6, (byte)68, (byte)198, (byte)161, (byte)81, (byte)39, (byte)217, (byte)178, (byte)149, (byte)69, (byte)64, (byte)160, (byte)187, (byte)225, (byte)163, (byte)5, (byte)86, (byte)152, (byte)45, (byte)78, (byte)159, (byte)222, (byte)95, (byte)100, (byte)37, (byte)241, (byte)77, (byte)75, (byte)113, (byte)52, (byte)65, (byte)181, (byte)93, (byte)199, (byte)59, (byte)155, (byte)74, (byte)237, (byte)204, (byte)146, (byte)172, (byte)227, (byte)146, (byte)126, (byte)55, (byte)245, (byte)125, (byte)12, (byte)253, (byte)94, (byte)117, (byte)129, (byte)250, (byte)81, (byte)44, (byte)143, (byte)73, (byte)97, (byte)169, (byte)235, (byte)11, (byte)128, (byte)248, (byte)168, (byte)7, (byte)70, (byte)114, (byte)138, (byte)85, (byte)255, (byte)70, (byte)71, (byte)31, (byte)52, (byte)37, (byte)6, (byte)59, (byte)157, (byte)83, (byte)100, (byte)47, (byte)94, (byte)222, (byte)30, (byte)132, (byte)214, (byte)19, (byte)8, (byte)26, (byte)250, (byte)92, (byte)34, (byte)208, (byte)81, (byte)40, (byte)91, (byte)214, (byte)59, (byte)148, (byte)59, (byte)86, (byte)93, (byte)137, (byte)138, (byte)5, (byte)104, (byte)84, (byte)19, (byte)229, (byte)60, (byte)60, (byte)108, (byte)101, (byte)37, (byte)255, (byte)31, (byte)227, (byte)78, (byte)61, (byte)220, (byte)112, (byte)240, (byte)213, (byte)100, (byte)80, (byte)253, (byte)164, (byte)139, (byte)161, (byte)46, (byte)16, (byte)78, (byte)157, (byte)235, (byte)159, (byte)184, (byte)24, (byte)129, (byte)225, (byte)196, (byte)189, (byte)242, (byte)93, (byte)146, (byte)71, (byte)244, (byte)80, (byte)200, (byte)101, (byte)146, (byte)121, (byte)104, (byte)231, (byte)115, (byte)52, (byte)244, (byte)65, (byte)79, (byte)117, (byte)167, (byte)80, (byte)225, (byte)57, (byte)84, (byte)110, (byte)58, (byte)138, (byte)115, (byte)157};

			BigInteger N = new BigInteger(1, n);
			BigInteger E = new BigInteger(1, e);
			BigInteger D = new BigInteger(1, d);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(N, E);
			RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(N, D);
			rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
			rsaPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

			Digest digest = new SHA256Digest();
			byte[] bytes = rsaPublicKey.getEncoded();
			digest.update(bytes, 0, bytes.length);
			byte[] out = new byte[digest.getDigestSize()];
			/*int result =*/ digest.doFinal(out, 0);
			String thumbprint = BASE64.encodeBytes(out, 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			rsa15AesGcm128HeaderStr = "{\"alg\":\"" + JWA.RSA1_5 + "\",\r\n"+
			" \"enc\":\"" + JWA.A128GCM + "\",\r\n"+
			" \"iv\":\"yv66vvrO263eyviI\",\r\n" +
			" \"x5t\":\"" + thumbprint + "\"}";
			rsa15AesGcm128HeaderStrb64 = BASE64.encodeBytes(rsa15AesGcm128HeaderStr.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			rsa15AesGcm256HeaderStr = "{\"alg\":\"" + JWA.RSA1_5 + "\",\r\n"+
			" \"enc\":\"" + JWA.A256GCM + "\",\r\n"+
			" \"iv\":\"yv66vvrO263eyviI\",\r\n" +
			" \"x5t\":\"" + thumbprint + "\"}";
			rsa15AesGcm256HeaderStrb64 = BASE64.encodeBytes(rsa15AesGcm256HeaderStr.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			rsaOaepAesCbc128HeaderStr = "{\"alg\":\"" + JWA.RSA_OAEP + "\",\r\n"+
			" \"enc\":\"" + JWA.A128CBC + "\",\r\n"+
			" \"x5t\":\"" + thumbprint + "\"}";
			rsaOaepAesCbc128HeaderStrb64 = BASE64.encodeBytes(rsaOaepAesCbc128HeaderStr.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			rsaOaepAesCbc192HeaderStr = "{\"alg\":\"" + JWA.RSA_OAEP + "\",\r\n"+
			" \"enc\":\"" + JWA.A192CBC + "\",\r\n"+
			" \"x5t\":\"" + thumbprint + "\"}";
			rsaOaepAesCbc192HeaderStrb64 = BASE64.encodeBytes(rsaOaepAesCbc192HeaderStr.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			rsaOaepAesCbc256HeaderStr = "{\"alg\":\"" + JWA.RSA_OAEP + "\",\r\n"+
			" \"enc\":\"" + JWA.A256CBC + "\",\r\n"+
			" \"x5t\":\"" + thumbprint + "\"}";
			rsaOaepAesCbc256HeaderStrb64 = BASE64.encodeBytes(rsaOaepAesCbc256HeaderStr.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			epbeb64 = BASE64.encodeBytes(epbe.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			ae128b64 = BASE64.encodeBytes(ae128.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);
			ae192b64 = BASE64.encodeBytes(ae192.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);
			ae256b64 = BASE64.encodeBytes(ae256.getBytes("utf-8"), 
			BASE64.DONT_BREAK_LINES | BASE64.URL);

			//      byte[] keybytes128 = new byte[16];
			//      SecureRandom random = new SecureRandom();
			//      random.nextBytes(keybytes128);
			//      keybytes128B64 = BASE64.encodeBytesNoBreaks(keybytes128);
			//      System.out.println("keybytes128B64=" + keybytes128B64);
			//      
			//      byte[] keybytes256 = new byte[32];
			//      random.nextBytes(keybytes256);
			//      keybytes256B64 = BASE64.encodeBytesNoBreaks(keybytes256);
			//      System.out.println("keybytes256B64=" + keybytes256B64);

			keybytes128B64="wkp7v4KkBox9rSwVBXT+aA==";
			keybytes256B64="aRjpB3nhFA7B7B+sKwfM4OhU+6kLeg0W7p6OFbn7AfE=";

		} catch (Exception e) {
			
			fail(e.getMessage());
		}
	}
	
	
	public void testJoeEncoding()
		throws UnsupportedEncodingException {

		byte[] bytes = joeStr.getBytes("utf-8");
		String base64urlStr = BASE64.encodeBytes(bytes, BASE64.DONT_BREAK_LINES | BASE64.URL);
		String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
		assertEquals(expected, base64urlStr);
	}
	
	
	public void testHS256Encoding()
		throws UnsupportedEncodingException {

		byte[] bytes = hs256.getBytes("utf-8");
		String base64urlStr = BASE64.encodeBytes(bytes, BASE64.DONT_BREAK_LINES | BASE64.URL);
		String expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
		assertEquals(expected, base64urlStr);
	}

  
	public void testES256Encoding() 
		throws UnsupportedEncodingException {

		byte[] bytes = es256.getBytes("utf-8");
		String base64urlStr = BASE64.encodeBytes(bytes, BASE64.DONT_BREAK_LINES | BASE64.URL);
		String expected = "eyJhbGciOiJFUzI1NiJ9";
		assertEquals(expected, base64urlStr);
	}
	
	
	private void testHMACSHA(final Base64URL headerB64, final Base64URL expectedSignatureB64) 
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(headerB64);
		
		StringBuilder sb = new StringBuilder(headerB64.toString());
		sb.append('.');
		sb.append(Base64URL.encode(joeStr));
		byte[] signableContent = sb.toString().getBytes("UTF-8");
		
		Base64URL signature = JWS.hmacSign(header, signableContent, hsKey);
		
		assertEquals(expectedSignatureB64, signature);
		
		assertTrue(JWS.hmacVerify(header, signableContent, signature, hsKey));
	}
  
	public void testHS256() 
		throws Exception {
		
		testHMACSHA(new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"), 
		            new Base64URL("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")); 
	}

	public void testHS384() 
		throws Exception {
		
		testHMACSHA(new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzM4NCJ9"), 
			    new Base64URL("TUfcA4Xjq_veopvw1fiFG99UswFSMvxYisxxBb0kHQ7w8He3OkvmELPo0uy3RuR0")); 
	}

	public void testHS512() 
		throws Exception {
		
		testHMACSHA(new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzUxMiJ9"), 
			    new Base64URL("iXxB-yPnHRvriuSAfTrwz-gr5WYC6tg7gIq9JndRI9Uqn4D6twBgsJuQsQks6WqAC6OB23Lvdht79p_lA6jE8g")); 
	}
	
	
	private void testRSASHA(final Base64URL headerB64, final Base64URL expectedSignatureB64) 
		throws Exception {
		
		JWSHeader header = JWSHeader.parse(headerB64);
		
		StringBuilder sb = new StringBuilder(headerB64.toString());
		sb.append('.');
		sb.append(Base64URL.encode(joeStr));
		byte[] signableContent = sb.toString().getBytes("UTF-8");
		
		Base64URL signature = JWS.rsaSign(header, signableContent, rsaPrivKey);
		
		assertEquals(expectedSignatureB64, signature);
		
		assertTrue(JWS.rsaVerify(header, signableContent, signature, rsaPublicKey));
	}

	
	public void testRS256()
		throws Exception {
	
		Base64URL headerB64 = new Base64URL("eyJhbGciOiJSUzI1NiJ9");
		Base64URL expectedSignature = new Base64URL("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw");
		
		testRSASHA(headerB64, expectedSignature);
	}
	
  
	public void testRS384()
		throws Exception {
		
		Base64URL headerB64 = new Base64URL("eyJhbGciOiJSUzM4NCJ9");
		Base64URL expectedSignature = new Base64URL("UqgNjrJOGhk4wfoSG6Uvrt9GcKu-TgPwInExALrMBadg1pol1uTw7mZADTddAWsC6ZzdFiTFUmIi7DuD38ftLAZoW4qezdAO7RYf1yZDsbT20bt8DJJN1I4VovL2PLg80B6x6ug-kaW8k5LaM5ce0dk1zgWhjafKC3Mb4UNLL8f9fqVMkHpdWYRjF6QjTz12Ap-gq-tPyUoWSdvzCIYOcZ9-08SQQdUTTgsNF1Qwu3TqeWPqzNJwmWHiHMmaV8I4ktMFEX-AiEBa55KsfYTx0jSbTHP-odqmnLQJ4n-oQJ2RSXy0HQP6BkdiwDHdoMUk4z_wAeOsfDTs_mLxTgOInQ");
		
		testRSASHA(headerB64, expectedSignature);
	}
	
	
	public void testECDSAsignature_Draft01() 
		throws Exception {
	
		String signedJWTString = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
	
		SignedJWT signedJWT = SignedJWT.parse(signedJWTString);
	
		byte[] x = {127, (byte)205, (byte)206, (byte)39, (byte)112, (byte)246, (byte)196, (byte)93, (byte)65, (byte)131, (byte)203, (byte)238, (byte)111, (byte)219, (byte)75, (byte)123, (byte)88, (byte)7, (byte)51, (byte)53, (byte)123, (byte)233, (byte)239, (byte)19, (byte)186, (byte)207, (byte)110, (byte)60, (byte)123, (byte)209, (byte)84, (byte)69};
		byte[] y = {(byte)199, (byte)241, (byte)68, (byte)205, (byte)27, (byte)189, (byte)155, (byte)126, (byte)135, (byte)44, (byte)223, (byte)237, (byte)185, (byte)238, (byte)185, (byte)244, (byte)179, (byte)105, (byte)93, (byte)110, (byte)169, (byte)11, (byte)36, (byte)173, (byte)138, (byte)70, (byte)35, (byte)40, (byte)133, (byte)136, (byte)229, (byte)173};

		BigInteger xInt = new BigInteger(1, x);
		BigInteger yInt = new BigInteger(1, y);

		assertTrue(signedJWT.ecdsaVerify(xInt, yInt));
	}
	
	
	public void testEDSAsignature() 
		throws Exception {
		
			//    byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131, (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13, (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10, (byte)175, (byte)236, 62};
			//    byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136, (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30, (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108, (byte)206, 8, 23, 35};
			byte[] d = {(byte)243, (byte)189, 12, 7, (byte)168, 31, (byte)185, 50, 120, 30, (byte)213, 39, 82, (byte)246, 12, (byte)200, (byte)154, 107, (byte)229, (byte)229, 25, 52, (byte)254, 1, (byte)147, (byte)141, (byte)219, 85, (byte)216, (byte)247, 120, 1};

			//    "secp256r1 [NIST P-256, X9.62 prime256v1]", "1.2.840.10045.3.1.7"
			
			SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWA.ES256), new ClaimsSet(joeStr));
			signedJWT.ecdsaSign(new BigInteger(1, d));
			String signedJWTString = signedJWT.serialize();
			
			String[] split = signedJWTString.split("\\.");
			assertEquals(3, split.length);
			assertEquals("eyJhbGciOiJFUzI1NiJ9", split[0]);
			assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", split[1]);
			byte[] signatureBytes = BASE64.decodeUrl(split[2]);
			assertEquals(64, signatureBytes.length);
			
			byte[] x = {48, (byte)160, 66, 76, (byte)210, 28, 41, 68, (byte)131, (byte)138, 45, 117, (byte)201, 43, 55, (byte)231, 110, (byte)162, 13, (byte)159, 0, (byte)137, 58, 59, 78, (byte)238, (byte)138, 60, 10, (byte)175, (byte)236, 62};
			byte[] y = {(byte)224, 75, 101, (byte)233, 36, 86, (byte)217, (byte)136, (byte)139, 82, (byte)179, 121, (byte)189, (byte)251, (byte)213, 30, (byte)232, 105, (byte)239, 31, 15, (byte)198, 91, 102, 89, 105, 91, 108, (byte)206, 8, 23, 35};
			
			signedJWT = SignedJWT.parse(signedJWTString);
			
			assertTrue(signedJWT.ecdsaVerify(new BigInteger(1, x), new BigInteger(1, y)));
	}
	
	
	private void testRsa(final String name, final String jwtHeaderSegment, final String jwtHeaderSegmentB64)
		throws Exception {

		// System.out.println("jwtHeaderSegment: " + name + " " + jwtHeaderSegment);

		JWEHeader header = JWEHeader.parse(jwtHeaderSegment);
		
		ClaimsSet claimsSet = new ClaimsSet(joeStr);
		
		JWE.Parts jweParts = JWE.rsaEncrypt(header, claimsSet.toBytes(), rsaPublicKey);
		
		byte[] clearText = JWE.rsaDecrypt(header, jweParts.getEncryptedKey(), jweParts.getCipherText(), rsaPrivKey);
		
		assertEquals(joeStr, new ClaimsSet(clearText).toString());
	}


	public void testRE128()
		throws Exception {
		
		testRsa("rsaOaepAesCbc128", rsaOaepAesCbc128HeaderStr, rsaOaepAesCbc128HeaderStrb64);
	}


	public void testRE192() 
		throws Exception {
		
		testRsa("rsaOaepAesCbc192", rsaOaepAesCbc192HeaderStr, rsaOaepAesCbc192HeaderStrb64);
	}


	public void testRE256() 
		throws Exception {
		
		testRsa("rsaOaepAesCbc256", rsaOaepAesCbc256HeaderStr, rsaOaepAesCbc256HeaderStrb64);
	}
	
	
	public void testRE128Gcm() 
		throws Exception {
		
		testRsa("rsa15AesGcm128", rsa15AesGcm128HeaderStr, rsa15AesGcm128HeaderStrb64);
	}
	

	public void testRE256Gcm() 
		throws Exception {
		
		testRsa("rsa15AesGcm256", rsa15AesGcm256HeaderStr, rsa15AesGcm256HeaderStrb64);
	}
	
	
	public void testAesGcmJWE()
		throws Exception {

		JWEHeader header = new JWEHeader(JWA.A128GCM);
		
		byte[] ivBytes = Hex.decode("cafebabefacedbaddecaf888");
		header.setInitializationVector(Base64URL.encode(ivBytes));

		byte[] keyData = BASE64.decode(keybytes128B64);
		SecretKey secretKey = new SecretKeySpec(keyData , "AES");
		
		ClaimsSet claimsSet = new ClaimsSet(joeStr);
		JWE.Parts jweParts = JWE.aesEncrypt(header, claimsSet.toBytes(), secretKey);
		
		Base64URL expectedCipherText = new Base64URL("H7I-QNvM8VtMylQfBbbqyrT8xiFcVv-7CZTn-dkXr10dpIOmzjMbqjmbqevK2aAoRu4s5DhU8dbeu8SbRJTCDYYAkYfOo_Hc5NY6B5-VwhnOWc0sres");
		
		assertEquals(expectedCipherText, jweParts.getCipherText());
		
		byte[] decryptedClearText = JWE.aesDecrypt(header, jweParts.getCipherText(), secretKey);
		
		assertEquals(joeStr, new ClaimsSet(decryptedClearText).toString());
	}
	
	
	  public void testAE128()
	  	throws Exception {
		
		JWEHeader header = new JWEHeader(JWA.AE128);
		ClaimsSet claimsSet = new ClaimsSet(joeStr);
		
		KeyGenerator keygen;
		
		try {
			keygen = KeyGenerator.getInstance("AES");
		
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
		
		keygen.init(128);
		
		SecretKey key = keygen.generateKey();
		
		JWE.Parts jweParts = JWE.aesEncrypt(header, claimsSet.toBytes(), key);

		byte[] decryptedClearText = JWE.aesDecrypt(header, jweParts.getCipherText(), key);
		
		assertEquals(joeStr, new ClaimsSet(decryptedClearText).toString());
	}

  
	private void printBytes(final String label, final byte[] bytes) {

		System.out.print(label + "\n[");
	
		for (int i=0; i<bytes.length-1; i++) {
			System.out.print(Integer.toString(bytes[i]) + ", ");
		}
		
		System.out.println(Integer.toString(bytes[bytes.length-1]) + "]");
	}

  
	public void testAE192fixedKey()
		throws Exception {

		JWEHeader header = new JWEHeader(JWA.AE192);
		ClaimsSet claimsSet = new ClaimsSet(joeStr);
		
		final byte[] encodedKey = new byte[]{126, (byte)-34, (byte)-48, (byte)-34, (byte)61, (byte)72, (byte)-63, (byte)-36, (byte)14, (byte)53, (byte)-27, (byte)-7, (byte)-35, (byte)-57, (byte)59, (byte)-89, (byte)51, (byte)84, (byte)115, (byte)-119, (byte)-1, (byte)-125, (byte)-115, (byte)108};

		SecretKey key = new SecretKeySpec(encodedKey, "AES");
		// printBytes("fixed AES192 keybytes", key.getEncoded());

		JWE.Parts jweParts = JWE.aesEncrypt(header, claimsSet.toBytes(), key);

		byte[] decryptedClearText = JWE.aesDecrypt(header, jweParts.getCipherText(), key);
		
		assertEquals(joeStr, new ClaimsSet(decryptedClearText).toString());
	}
	
	
	public void testAE192()
		throws Exception {
		
		JWEHeader header = new JWEHeader(JWA.AE192);
		ClaimsSet claimsSet = new ClaimsSet(joeStr);

		KeyGenerator keygen;
		
		try {
			keygen = KeyGenerator.getInstance("AES");
		
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}

		keygen.init(192);
		SecretKey key = keygen.generateKey();
		// printBytes("AES192 keybytes", key.getEncoded());

		JWE.Parts jweParts = JWE.aesEncrypt(header, claimsSet.toBytes(), key);

		byte[] decryptedClearText = JWE.aesDecrypt(header, jweParts.getCipherText(), key);
		
		assertEquals(joeStr, new ClaimsSet(decryptedClearText).toString());
	}

	public void testAE256()
		throws Exception {
		
		JWEHeader header = new JWEHeader(JWA.AE256);
		ClaimsSet claimsSet = new ClaimsSet(joeStr);

		KeyGenerator keygen;
		
		try {
			keygen = KeyGenerator.getInstance("AES");
		
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}

		keygen.init(256);
		SecretKey key = keygen.generateKey();

		JWE.Parts jweParts = JWE.aesEncrypt(header, claimsSet.toBytes(), key);

		byte[] decryptedClearText = JWE.aesDecrypt(header, jweParts.getCipherText(), key);
		
		assertEquals(joeStr, new ClaimsSet(decryptedClearText).toString());
	}


}
