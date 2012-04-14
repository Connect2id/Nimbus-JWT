package com.nimbusds.jwt;


import junit.framework.TestCase;


/**
 * Tests GZIP compression.
 *
 * @version 1.10 (2012-04-02)
 */
public class CompressionUtilsTest extends TestCase {


	public void testNONE()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
		
		JWEHeader header = new JWEHeader(JWA.A128GCM);
		header.setCompressionAlgorithm(CompressionAlgorithm.NONE);
	
		byte[] compressed = CompressionUtils.compressIfRequired(header, textBytes);
		assertTrue(compressed.length == textBytes.length);
		
		for (int i=0; i < textBytes.length; i++)
			assertEquals(textBytes[i], compressed[i]);
	}
	
	
	public void testNull()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
		
		JWEHeader header = new JWEHeader(JWA.A128GCM);
		header.setCompressionAlgorithm(null);
	
		byte[] compressed = CompressionUtils.compressIfRequired(header, textBytes);
		assertTrue(compressed.length == textBytes.length);
		
		for (int i=0; i < textBytes.length; i++)
			assertEquals(textBytes[i], compressed[i]);
	}
	
	
	public void testGZIP()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
		
		JWEHeader header = new JWEHeader(JWA.A128GCM);
		header.setCompressionAlgorithm(CompressionAlgorithm.GZIP);
	
		byte[] compressed = CompressionUtils.compressIfRequired(header, textBytes);
		assertTrue(compressed.length > textBytes.length);
		
		byte[] textBytesDecompressed = CompressionUtils.decompressIfRequired(header, compressed);
		String textDecompressed = new String(textBytesDecompressed, "UTF-8");
		
		assertEquals(text.length(), textDecompressed.length());
		assertEquals(text, textDecompressed);
	}
}
