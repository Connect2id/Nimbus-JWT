/*
  Name:         net.sourceforge.lightcrypto.SafeObject
  Licensing:    LGPL (lesser GNU Public License)
  API:          Bouncy Castle (http://www.bouncycastle.org) lightweight API

  Disclaimer:

  COVERED CODE IS PROVIDED UNDER THIS LICENSE ON AN "AS IS" BASIS, WITHOUT WARRANTY OF ANY KIND,
  EITHER EXPRESSED OR IMPLIED, INCLUDING, WITHOUT LIMITATION, WARRANTIES THAT THE COVERED CODE
  IS FREE OF DEFECTS, MERCHANTABLE, FIT FOR A PARTICULAR PURPOSE OR NON-INFRINGING. THE ENTIRE
  RISK AS TO THE QUALITY AND PERFORMANCE OF THE COVERED CODE IS WITH YOU. SHOULD ANY COVERED CODE
  PROVE DEFECTIVE IN ANY RESPECT, YOU (NOT THE INITIAL DEVELOPER OR ANY OTHER CONTRIBUTOR)
  ASSUME THE COST OF ANY NECESSARY SERVICING, REPAIR OR CORRECTION. THIS DISCLAIMER OF WARRANTY
  CONSTITUTES AN ESSENTIAL PART OF THIS LICENSE. NO USE OF ANY COVERED CODE IS AUTHORIZED
  HEREUNDER EXCEPT UNDER THIS DISCLAIMER.

  (C) Copyright 2003 Gert Van Ham

*/
package com.nimbusds.jwt;


import java.io.UnsupportedEncodingException;
import java.util.Arrays;


import org.bouncycastle.util.encoders.Base64;


/**
 * Erasable byte array store.
 *
 * @author Gert Van Ham, Vladimir Dzhuvinov
 * @version 1.10 (2012-03-09)
 */
class SafeObject {

	
	/**
	 * The default charset.
	 */
	public static String CHARSET = "utf-8";
	
	
	/**
	 * The safe content.
	 */
	private byte[] content;

	
	/**
	 * Sets the safe object content.
	 *
	 * @param content The byte array content.
	 */
	public void set(final byte[] content) {

		this.content = content;
	}
	
	
	/**
	 * Gets the safe object content.
	 *
	 * @return The safe object content.
	 */
	public byte[] get() {
	
		return content;
	}
	
    
	/**
	 * Gets the safe object content as a string buffer.
	 *
	 * @return The safe object content as a string buffer.
	 * @exception Exception for all errors 
	 */  
	public StringBuffer getStringBuffer() {
	
		try {
			return new StringBuffer(new String(content, CHARSET));
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
			return new StringBuffer();
		}
	}
	
	
	/**
	 * Gets the safe object content as a Base64 string.
	 *
	 * @return The safe object content as a Base64 string.
	 */
	public String getBase64() {
	
		return new String(Base64.encode(content));
    	}
	

    	/**
	 * Gets the byte length of the safe object content.
	 *
	 * @return The byte length, -1 if {@code null}.
	 */
	public int getLength() {
	
		if (content == null)
			return -1;
	
		return content.length;
	}

	
	/**
	 * Clears the safe object content.
	 */
	public void clear() {
	
		if (content == null)
			return;
			
		final byte zero = 0;
			
		Arrays.fill(content, zero);
	}                       
} 

