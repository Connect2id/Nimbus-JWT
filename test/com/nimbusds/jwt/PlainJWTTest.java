package com.nimbusds.jwt;


import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;

import junit.framework.TestCase;


/**
 * Tests plain JWT parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-26)
 */
public class PlainJWTTest extends TestCase {
	

	public void testSerializeAndParse() {

		JSONObject claims = new JSONObject();
		claims.put("iss", "http://nimbusds.com");
		claims.put("exp", 123);
		claims.put("act", true);

		PlainJWT jwt = new PlainJWT(new ClaimsSet(claims));
		
		assertNotNull(jwt.getHeader());
		assertNotNull(jwt.getClaimsSet());
		
		ReadOnlyPlainJWTHeader h = jwt.getHeader();
		assertEquals(JWA.NONE, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		assertTrue(h.getCustomParameters().isEmpty());
		
		
		String s = jwt.serialize();
		
		try {
			jwt = PlainJWT.parse(s);
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}
		
		h = jwt.getHeader();
		assertEquals(JWA.NONE, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		assertTrue(h.getCustomParameters().isEmpty());
		
		claims = jwt.getClaimsSet().toJSONObject();
		assertNotNull(claims);
		assertEquals("http://nimbusds.com", (String)claims.get("iss"));
		assertEquals(123, new Integer((Integer)claims.get("exp")).intValue());
		assertTrue((Boolean)claims.get("act"));
	}
}
