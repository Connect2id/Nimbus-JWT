package com.nimbusds.jwt;


import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;

import junit.framework.TestCase;


/**
 * Tests signed JWTs.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-26)
 */
public class SignedJWTTest extends TestCase {
	

	public void testConstructor() {

		JWSHeader h = new JWSHeader(JWA.HS256);
		h.setType(Header.Type.JWT);

		JSONObject claims = new JSONObject();
		claims.put("iss", "http://nimbusds.com");
		claims.put("exp", 123);
		claims.put("act", true);

		SignedJWT jwt = new SignedJWT(h, new ClaimsSet(claims));
		
		assertNotNull(jwt.getHeader());
		assertNotNull(jwt.getClaimsSet());
		
		ReadOnlyJWSHeader hOut = jwt.getHeader();
		assertEquals(JWA.HS256, hOut.getAlgorithm());
		assertEquals(Header.Type.JWT, hOut.getType());
		assertTrue(hOut.getCustomParameters().isEmpty());
		
		assertNull(jwt.getSignature());
		
		assertEquals(SignedJWT.State.UNSIGNED, jwt.getState());
	}
}
