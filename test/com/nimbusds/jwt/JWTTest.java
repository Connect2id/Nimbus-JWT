package com.nimbusds.jwt;


import junit.framework.TestCase;


/**
 * Tests JSON Web Key (JWK) parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9.1 (2012-03-19)
 */
public class JWTTest extends TestCase {


	public void testSplitFull() {

		String s = "abc.def.ghi";
		
		Base64URL[] parts = null;
		
		try {
			parts = JWT.split(s);
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
	}
	
	
	public void testSplitEmptyThirdPart() {

		String s = "abc.def.";
		
		Base64URL[] parts = null;
		
		try {
			parts = JWT.split(s);
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("def", parts[1].toString());
		assertEquals("", parts[2].toString());
	}
	
	
	public void testSplitEmptySecondPart() {

		String s = "abc..ghi";
		
		Base64URL[] parts = null;
		
		try {
			parts = JWT.split(s);
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(3, parts.length);
		
		assertEquals("abc", parts[0].toString());
		assertEquals("", parts[1].toString());
		assertEquals("ghi", parts[2].toString());
	}
	
	
	public void testSplitException() {

		String s = "abc.def";
		
		Base64URL[] parts = null;
		
		try {
			parts = JWT.split(s);
			
			fail("Failed to raise exception");
			
		} catch (JWTException e) {
		
			// ok
		}
	}
}
