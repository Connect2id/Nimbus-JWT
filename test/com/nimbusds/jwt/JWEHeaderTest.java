package com.nimbusds.jwt;


import java.net.MalformedURLException;
import java.net.URL;

import junit.framework.TestCase;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-26)
 */
public class JWEHeaderTest extends TestCase {


	public void testParse() {
	
		// Example header from JWE spec
		
		String s = "{\"alg\":\"RSA1_5\","+
			    "\"enc\":\"A256GCM\"," +
			    "\"iv\":\"__79_Pv6-fg\"," +
			    "\"jku\":\"https://example.com/public_key.jwk\"}";
	
		JWEHeader h = null;
		
		try {
			h = JWEHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertNull(h.getType());
		assertEquals(JWA.RSA1_5, h.getAlgorithm());
		assertEquals(JWA.A256GCM, h.getEncryptionMethod());
		assertEquals(new Base64URL("__79_Pv6-fg"), h.getInitializationVector());
		assertEquals("https://example.com/public_key.jwk", h.getJWKURL().toString());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		JWEHeader h = new JWEHeader(JWA.RSA1_5);
		
		h.setType(Header.Type.JWT);
		h.setEncryptionMethod(JWA.A256GCM);
		h.setIntegrityAlgorithm(null);
		h.setInitializationVector(new Base64URL("abc"));
		h.setCompressionAlgorithm(CompressionAlgorithm.GZIP);
		h.setJWKURL(new URL("https://example.com/jku.json"));
		h.setKeyID("1234");
		
		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final JWKKeyObject.Use use = JWKKeyObject.Use.ENCRYPTION;
		final String kid = "1234";
		
		RSAKeyObject jpk = new RSAKeyObject(mod, exp, use, kid);
		
		h.setPublicKey(jpk);
		h.setX509CertURL(new URL("https://example/cert.b64"));
		h.setX509CertThumbprint(new Base64URL("789iop"));
		
		Base64[] certChain = new Base64[3];
		certChain[0] = new Base64("asd");
		certChain[1] = new Base64("fgh");
		certChain[2] = new Base64("jkl");
		
		h.setX509CertChain(certChain);
		
		
		String s = h.toString();
		
		// Parse back
		
		try {
			h = JWEHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(JWA.RSA1_5, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		assertEquals(JWA.A256GCM, h.getEncryptionMethod());
		assertNull(h.getIntegrityAlgorithm());
		assertEquals("abc", h.getInitializationVector().toString());
		assertEquals(CompressionAlgorithm.GZIP, h.getCompressionAlgorithm());
		assertEquals("https://example.com/jku.json", h.getJWKURL().toString());
		assertEquals("1234", h.getKeyID());
		
		jpk = (RSAKeyObject)h.getPublicKey();
		assertNotNull(jpk);
		assertEquals("abc123", jpk.getModulus().toString());
		assertEquals("def456", jpk.getExponent().toString());
		assertEquals(JWKKeyObject.Use.ENCRYPTION, jpk.getUse());
		assertEquals("1234", jpk.getKeyID());
		
		assertEquals("https://example/cert.b64", h.getX509CertURL().toString());
		assertEquals("789iop", h.getX509CertThumbprint().toString());
		
		certChain = h.getX509CertChain();
		assertEquals(3, certChain.length);
		assertEquals("asd", certChain[0].toString());
		assertEquals("fgh", certChain[1].toString());
		assertEquals("jkl", certChain[2].toString());
	}
}
