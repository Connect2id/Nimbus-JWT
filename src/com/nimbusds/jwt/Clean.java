/*
  Name:         net.sourceforge.lightcrypto.Clean
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


import java.util.Arrays;


/**
 * Utility for zeroing byte arrays and string buffers.
 *
 * @author Gert Van Ham, Vladimir Dzhuvinov
 * @version 1.10 (2012-03-09)
 */
class Clean {


	/**
	 * Zero the specified byte array.
	 *
	 * @param bytes The byte array to zero.
	 */
	public static void blank(final byte[] bytes) {
	
		if (bytes == null)
			return;
	
		final byte zero = 0;
		
		Arrays.fill(bytes, zero);
	}
	
	
	/**
	 * Clears the specified string buffer.
	 *
	 * @param sb The string buffer to clear.
	 */
	public static void blank(final StringBuffer sb) {
	
		if (sb == null)
			return;
		
		sb.delete(0, sb.length());
	}
}

