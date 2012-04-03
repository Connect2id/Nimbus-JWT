package com.nimbusds.jwt;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;


/**
 * Tests plain JWT header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-26)
 */
public class PlainJWTHeaderTest extends TestCase {
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		PlainJWTHeader h = new PlainJWTHeader();
		
		assertEquals(JWA.NONE, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		
		Map<String,Object> customParams = new HashMap<String,Object>();
		
		customParams.put("xCustom", "abc");
		
		h.setCustomParameters(customParams);
		
		
		String s = h.toString();
		
		// Parse back
		
		try {
			h = PlainJWTHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(JWA.NONE, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		
		customParams = h.getCustomParameters();
		assertNotNull(customParams);
		assertFalse(customParams.isEmpty());
		assertEquals(1, customParams.size());
		assertEquals("abc", customParams.get("xCustom"));
	}
}
