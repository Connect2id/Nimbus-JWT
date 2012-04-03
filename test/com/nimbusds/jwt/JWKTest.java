package com.nimbusds.jwt;


import java.util.List;

import junit.framework.TestCase;


/**
 * Tests JSON Web Key (JWK) parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-19)
 */
public class JWKTest extends TestCase {


	public void testParse() {
	
		// The string is from the JWK spec
		String s =
			"{\"jwk\":" +
     			    "[" +
			       "{\"alg\":\"EC\"," +
        			"\"crv\":\"P-256\"," +
        			"\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
        			"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
        			"\"use\":\"enc\"," +
        			"\"kid\":\"1\"}," +
                        	" " +
			       "{\"alg\":\"RSA\"," +
        			"\"mod\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			   "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			   "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			   "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			   "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			   "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
        			"\"exp\":\"AQAB\"," +
        			"\"kid\":\"2011-04-29\"}" +
			     "]" +
			   "}";
   
   		JWK jwk = null;
		
		try {
			jwk = JWK.parse(s);
			
		} catch (JWKException e) {
		
			fail(e.getMessage());
		}
		
		List<JWKKeyObject> koList = jwk.getKeyObjectList();
		
		assertNotNull(koList);
		
		assertEquals(2, koList.size());
		
		JWKKeyObject ko = koList.get(0);
		
		assertNotNull(ko);
		
		assertTrue(ko instanceof ECKeyObject);
		
		assertEquals("1", ko.getKeyID());
		assertEquals(JWKKeyObject.Use.ENCRYPTION, ko.getUse());
		
		ECKeyObject ecko = (ECKeyObject)ko;
		
		assertEquals(ECKeyObject.Curve.P_256, ecko.getCurve());
		assertEquals("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecko.getX().toString());
		assertEquals("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecko.getY().toString());
	
	
		ko = koList.get(1);
		
		assertNotNull(ko);
		
		assertTrue(ko instanceof RSAKeyObject);
		
		assertEquals("2011-04-29", ko.getKeyID());
		assertNull(ko.getUse());
		
		RSAKeyObject rsako = (RSAKeyObject)ko;
		
		assertEquals("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			     "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			     "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			     "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			     "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			     "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", 
			     rsako.getModulus().toString());
			     
		assertEquals("AQAB", rsako.getExponent().toString());
	}
	
	
	public void testSerializeAndParse() {
	
		
		ECKeyObject ecko = new ECKeyObject(ECKeyObject.Curve.P_256, 
		                                   new Base64URL("abc"), 
						   new Base64URL("def"),
						   JWKKeyObject.Use.ENCRYPTION,
						   "1234");
		
		RSAKeyObject rsako = new RSAKeyObject(new Base64URL("abc"),
		                                      new Base64URL("def"),
						      JWKKeyObject.Use.SIGNATURE,
						      "5678");
		
		JWK jwk = new JWK();
		
		jwk.getKeyObjectList().add(ecko);
		jwk.getKeyObjectList().add(rsako);
		
		String s = jwk.toString();
		
		
		try {
			jwk = JWK.parse(s);
			
		} catch (JWKException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(jwk);
		assertEquals(2, jwk.getKeyObjectList().size());
		
		ecko = (ECKeyObject)jwk.getKeyObjectList().get(0);
		assertNotNull(ecko);
		assertEquals(ECKeyObject.Curve.P_256, ecko.getCurve());
		assertEquals("abc", ecko.getX().toString());
		assertEquals("def", ecko.getY().toString());
		assertEquals(JWKKeyObject.Use.ENCRYPTION, ecko.getUse());
		assertEquals("1234", ecko.getKeyID());
		
		rsako = (RSAKeyObject)jwk.getKeyObjectList().get(1);
		assertNotNull(rsako);
		assertEquals("abc", rsako.getModulus().toString());
		assertEquals("def", rsako.getExponent().toString());
		assertEquals(JWKKeyObject.Use.SIGNATURE, rsako.getUse());
		assertEquals("5678", rsako.getKeyID());
	}
	
}
