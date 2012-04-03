package com.nimbusds.jwt;

import java.io.UnsupportedEncodingException;

import junit.framework.TestCase;

public class BASE64Test extends TestCase {
	
	byte[] mJWTbytes = {0x3, (byte)236, (byte)255, (byte)224, (byte)193};

	// http://self-issued.info/docs/draft-jones-json-web-token-00.html#anchor4
	String joeStr = "{\"iss\":\"joe\",\r\n" +
			" \"exp\":1300819380,\r\n" +
			" \"http://example.com/is_root\":true}";


	public void testUrlencode() 
		throws Exception {

		String enc = BASE64.encodeBytes(mJWTbytes, BASE64.URL);
		assertEquals("A-z_4ME", enc);
	}
	
	
	public void testUrldecode() 
		throws Exception {

		byte[] decoded = BASE64.decodeUrl("A-z_4ME");
		assertEquals(mJWTbytes.length, decoded.length);
		assertEquals(mJWTbytes[0], decoded[0]);
		assertEquals(mJWTbytes[1], decoded[1]);
		assertEquals(mJWTbytes[2], decoded[2]);
		assertEquals(mJWTbytes[3], decoded[3]);
	}

	// http://self-issued.info/docs/draft-jones-json-web-token-00.html#anchor4
	public void test0() 
		throws UnsupportedEncodingException {

		byte[] bytes = joeStr.getBytes("utf-8");
		String base64urlStr = BASE64.encodeBytes(bytes, BASE64.DONT_BREAK_LINES | BASE64.URL);
		String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
		assertEquals(expected, base64urlStr);
	}

}
