package com.nimbusds.jwt;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


/**
 * GZIP utilities for {@link JWE} clear text compression and decompression.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-04-02)
 */
class CompressionUtils {


	/**
	 * Compresses the specified byte array if the 
	 * {@link CompressionAlgorithm "zip" parameter} of the JWE header is set
	 * to {@CompressionAlgorithm#GZIP "GZIP"}, else the bytes are returned 
	 * unmodified.
	 *
	 * @param header The JWE header. Must not be {@code null}.
	 * @param bytes  The JWE clear text to compress if required. Must not be 
	 *               {@code null}.
	 *
	 * @return The compressed bytes, unmodified if GZIP compression is not 
	 *         required by the "zip" JWE header parameter.
	 *
	 * @throws IOException If compression failed.
	 */
	public static byte[] compressIfRequired(final ReadOnlyJWEHeader header, final byte[] bytes)
		throws IOException {
	
		CompressionAlgorithm ca = header.getCompressionAlgorithm();
		
		if (ca == null || ca.equals(CompressionAlgorithm.NONE))
			return bytes;
	
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		
		GZIPOutputStream gzip = new GZIPOutputStream(out);
		gzip.write(bytes);
		gzip.close();
		
		return out.toByteArray();
	}
	
	
	/**
	 * Decompresses the specified byte array if the 
	 * {@link CompressionAlgorithm "zip" parameter} of the JWE header is set
	 * to {@CompressionAlgorithm#GZIP "GZIP"}, else the bytes are returned 
	 * unmodified.
	 *
	 * @param header The JWE header. Must not be {@code null}.
	 * @param bytes  The JWE clear text to decompress if required. Must not
	 *               be {@code null}.
	 *
	 * @return The decompressed bytes, unmodified if GZIP decompression is
	 *         not required by the "zip" JWE header parameter.
	 *
	 * @throws IOException If decompression failed.
	 */
	public static byte[] decompressIfRequired(final ReadOnlyJWEHeader header, final byte[] bytes)
		throws IOException {
		
		CompressionAlgorithm ca = header.getCompressionAlgorithm();
		
		if (ca == null || ca.equals(CompressionAlgorithm.NONE))
			return bytes;
		
		GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(bytes));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		
		// Transfer bytes from the compressed array to the output
		byte[] buf = new byte[1024];
		
		int len;
		
		while ((len = gzip.read(buf)) > 0)
			out.write(buf, 0, len);
 
		gzip.close();
		out.close();
		
		return out.toByteArray();
	}


	/**
	 * Prevents instantiation.
	 */
	private CompressionUtils() {
	
		// Nothing to do
	}
}
