package com.nimbusds.jwt;


import java.net.MalformedURLException;
import java.net.URL;

import junit.framework.TestCase;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.8 (2012-03-26)
 */
public class JWSHeaderTest extends TestCase {
	
	
	public void testParse() {
	
		// Example header from JWS spec
		
		String s = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
		
		JWSHeader h = null;
		
		try {
			h = JWSHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(Header.Type.JWT, h.getType());
		assertEquals(JWA.HS256, h.getAlgorithm());
	}
}
