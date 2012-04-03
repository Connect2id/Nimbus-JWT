/*
 * Copyright (c) 2011, Axel Nennker - http://axel.nennker.de/
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names xmldap, xmldap.org, xmldap.com nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.nimbusds.jwt;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


/**
 * Routines for JSON Web Signatures (JWS).
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-01">JWS draft 01</a>
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-03-30)
 */
public class JWS {


	/**
	 * Gets a Message Authentication Code (MAC) service for the specified
	 * HMAC-based JSON Web Algorithm (JWA).
	 *
	 * @param jwa The JSON Web Algorithm (JWA). Must be {@link JWA#HS256},
	 *            {@link JWA#HS384} or {@link JWA#HS512}. Must not be 
	 *            {@code null}.
	 *
	 * @return A MAC service instance.
	 *
	 * @throws JWSException If the algorithm is not HMAC-based or 
	 *                      unsupported.
	 */
	private static Mac getMAC(final JWA jwa)
		throws JWSException {
		
		// The internal crypto provider uses different alg names
		String internalName = null;
			
		switch (jwa) {

			case HS256:
				internalName = "HMACSHA256";
				break;

			case HS384:
				internalName = "HMACSHA384";
				break;

			case HS512:
				internalName = "HMACSHA512";
				break;

			default:
				throw new JWSException("Unsupported HMAC algorithm, must be HS256, HS384 or HS512");
		}
		
		try {
			return Mac.getInstance(internalName);
			
		} catch (NoSuchAlgorithmException e) {
		
			throw new JWSException("Unsupported HMAC algorithm:" + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Produces a JSON Web Signature (JWS) using the HMAC algorithm.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#HS256} (mandatory for JWS implementations)
	 *     <li>{@link JWA#HS384} 
	 *     <li>{@link JWA#HS512}
	 * </ul>
	 *
	 * @param alg             An "alg" parameter that matches one of the 
	 *                        supported HMAC algorithms. Must not be 
	 *                        {@code null}.
	 * @param signableContent The content to sign. Must not be {@code null}.
	 * @param sharedSecret    The HMAC shared secret. Must not be 
	 *                        {@code null}.
	 *
	 * @return The JSON Web Signature (JWS) bytes, Base64URL-encoded.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public static Base64URL hmacSign(final JWA alg, 
	                                 final byte[] signableContent, 
					 final byte[] sharedSecret)
		throws JWSException {
		
		Mac mac = getMAC(alg);
		
		try {
			mac.init(new SecretKeySpec(sharedSecret, mac.getAlgorithm()));
			
		} catch (InvalidKeyException e) {
		
			throw new JWSException("Invalid HMAC key: " + e.getMessage(), e);
		}
		
		mac.update(signableContent);
		
		return Base64URL.encode(mac.doFinal());
		
	}
	
	
	/**
	 * Produces a JSON Web Signature (JWS) using the HMAC algorithm.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#HS256} (mandatory for JWS implementations)
	 *     <li>{@link JWA#HS384} 
	 *     <li>{@link JWA#HS512}
	 * </ul>
	 *
	 * @param header          The JWS header with an "alg" parameter that
	 *                        matches one of the supported HMAC algorithms. 
	 *                        Must not be {@code null}.
	 * @param signableContent The content to sign. Must not be {@code null}.
	 * @param sharedSecret    The HMAC shared secret. Must not be 
	 *                        {@code null}.
	 *
	 * @return The JSON Web Signature (JWS) bytes, Base64URL-encoded.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public static Base64URL hmacSign(final ReadOnlyJWSHeader header, 
	                                 final byte[] signableContent, 
				         final byte[] sharedSecret)
		throws JWSException {
	
		return hmacSign(header.getAlgorithm(), signableContent, sharedSecret);
	}
	
	
	/**
	 * Verifies an HMAC-based JSON Web Signature (JWS) using the specified 
	 * shared secret.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#HS256} (mandatory for JWS implementations)
	 *     <li>{@link JWA#HS384} 
	 *     <li>{@link JWA#HS512}
	 * </ul>
	 *
	 * @param header        The JWS header with an "alg" parameter that
	 *                      matches one of the supported HMAC algorithms. 
	 *                      Must not be {@code null}.
	 * @param signedContent The signed content. Must not be {@code null}.
	 * @param signature     The signature to verify. Must not be 
	 *                      {@code null}.
	 * @param sharedSecret  The HMAC shared secret. Must not be 
	 *                      {@code null}.
	 *
	 * @return {@code true} if the signature is successfully verified, else 
	 *         {@code false}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public static boolean hmacVerify(final ReadOnlyJWSHeader header,
	                                 final byte[] signedContent,
					 final Base64URL signature,
					 final byte[] sharedSecret)
		throws JWSException {
		
		Mac mac = getMAC(header.getAlgorithm());
		
		try {
			mac.init(new SecretKeySpec(sharedSecret, mac.getAlgorithm()));
			
		} catch (InvalidKeyException e) {
		
			throw new JWSException("Invalid HMAC key: " + e.getMessage(), e);
		}
		
		mac.update(signedContent);
		
		Base64URL expectedSignature = Base64URL.encode(mac.doFinal());
		
		if (expectedSignature.equals(signature))
			return true;
		else
			return false;
	}
	
	
	/**
	 * Gets an RSA signer and verifier for the specified RSA-based JSON Web 
	 * Algorithm (JWA).
	 *
	 * @param jwa The JSON Web Algorithm (JWA). Must be {@link JWA#RS256},
	 *            {@link JWA#RS384} or {@link JWA#RS512}. Must not be 
	 *            {@code null}.
	 *
	 * @return The RSA signer and verifier.
	 *
	 * @throws JWSException If the algorithm is not RSA-based or 
	 *                      unsupported.
	 */
	private static Signature getRSASignerAndVerifier(final JWA jwa)
		throws JWSException {
		
		// The internal crypto provider uses different alg names
		String internalName = null;
			
		switch (jwa) {

			case RS256:
				internalName = "SHA256withRSA";
				break;

			case RS384:
				internalName = "SHA384withRSA";
				break;

			case RS512:
				internalName = "SHA512withRSA";
				break;

			default:
				throw new JWSException("Unsupported RSA algorithm, must be RS256, RS384 or RS512");
		}
		
		try {
			return Signature.getInstance(internalName);
			
		} catch (NoSuchAlgorithmException e) {
		
			throw new JWSException("Unsupported RSA algorithm:" + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Produces a JSON Web Signature (JWS) using the RSASSA-PKCS1-v1_5 
	 * algorithm.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#RS256} (recommended for JWS implementations)
	 *     <li>{@link JWA#RS384}
	 *     <li>{@link JWA#RS512}
	 * </ul>
	 *
	 * @param header          The JWS header with an "alg" parameter that
	 *                        matches one of the supported RSA algorithms. 
	 *                        Must not be {@code null}.
	 * @param signableContent The content to sign. Must not be {@code null}.
	 * @param privateKey      The private RSA key. Must not be {@code null}.
	 *
	 * @return The JSON Web Signature (JWS) bytes, Base64URL-encoded.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public static Base64URL rsaSign(final ReadOnlyJWSHeader header,
	                                final byte[] signableContent,
				        final RSAPrivateKey privateKey)
		throws JWSException {
	
		Signature signer = getRSASignerAndVerifier(header.getAlgorithm());
		
		try {
			signer.initSign(privateKey);
			signer.update(signableContent);
			return Base64URL.encode(signer.sign());
			
		} catch (InvalidKeyException e) {
		
			throw new JWSException("Invalid private RSA key: " + e.getMessage(), e);

		} catch (SignatureException e) {
		
			throw new JWSException("Signature exception: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Verifies an RSA-based JSON Web Signature (JWS) using the specified 
	 * public RSA key.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#RS256} (recommended for JWS implementations)
	 *     <li>{@link JWA#RS384}
	 *     <li>{@link JWA#RS512}
	 * </ul>
	 *
	 * @param header        The JWS header with an "alg" parameter that
	 *                      matches one of the supported RSA algorithms. 
	 *                      Must not be {@code null}.
	 * @param signedContent The signed content. Must not be {@code null}.
	 * @param signature     The signature to verify. Must not be 
	 *                      {@code null}.
	 * @param publicKey     The public RSA key to verify the signature. Must
	 *                      not be {@code null}.
	 *
	 * @return {@code true} if the signature is successfully verified, else 
	 *         {@code false}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public static boolean rsaVerify(final ReadOnlyJWSHeader header, 
	                                final byte[] signedContent, 
				        final Base64URL signature,
				        final RSAPublicKey publicKey)
		throws JWSException {
		
		Signature verifier = getRSASignerAndVerifier(header.getAlgorithm());
		
		try {
			verifier.initVerify(publicKey);
			verifier.update(signedContent);
			return verifier.verify(signature.decode());
			
		} catch (InvalidKeyException e) {
		
			throw new JWSException("Invalid public RSA key: " + e.getMessage(), e);
		
		} catch (SignatureException e) {
		
			throw new JWSException("RSA signature exception: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Encapsulates the initial ECDSA setup parameters.
	 */
	private static class ECDSAParameters {
	
		/**
		 * The X9 EC parameters.
		 */
		private final X9ECParameters x9ECParams;
		
		
		/**
		 * The digest method.
		 */
		private final Digest digest;
		
		
		/**
		 * Creates a new initial ECDSA setup parameters instance.
		 *
		 * @param x9ECParams The X9 EC parameters.
		 * @param digest     The digest method.
		 */
		public ECDSAParameters(final X9ECParameters x9ECParams, Digest digest) {
		
			this.x9ECParams = x9ECParams;
			this.digest = digest;
		}
		
		
		/**
		 * Gets the X9 EC parameters.
		 *
		 * @return The X9 EC parameters.
		 */
		public X9ECParameters getX9ECParameters() {
		
			return x9ECParams;
		}
		
		
		/**
		 * Gets the digest method.
		 *
		 * @return The digest method.
		 */
		public Digest getDigest() {
		
			return digest;
		}
	}
	
	
	/**
	 * Gets the initial parameters for the specified ECDSA-based JSON Web 
	 * Algorithm (JWA).
	 *
	 * @param jwa The JSON Web Algorithm (JWA). Must be {@link JWA#ES256},
	 *            {@link JWA#ES384} or {@link JWA#ES512}. Must not be 
	 *            {@code null}.
	 *
	 * @return The initial ECDSA parameters.
	 *
	 * @throws JWSException If the algorithm is not ECDSA-based or 
	 *                      unsupported.
	 */
	private static ECDSAParameters getECDSAParameters(final JWA jwa)
		throws JWSException {
		
		DERObjectIdentifier oid = null;
		Digest digest = null;
		
		switch (jwa) {

			case ES256:
				oid = SECObjectIdentifiers.secp256r1;
				digest = new SHA256Digest();
				break;

			case ES384:
				oid = SECObjectIdentifiers.secp384r1;
				digest = new SHA384Digest();
				break;

			case ES512:
				oid = SECObjectIdentifiers.secp521r1;
				digest = new SHA512Digest();
				break;

			default:
				throw new JWSException("Unsupported ECDSA algorithm, must be ES256, ES384 or ES512");
		}

		X9ECParameters x9ECParams = SECNamedCurves.getByOID(oid);
		
		return new ECDSAParameters(x9ECParams, digest);
	}
	
	
	/**
	 * Produces a JSON Web Signature (JWS) using the ECDSA algorithm.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#ES256} (recommended for JWS implementations)
	 *     <li>{@link JWA#ES384}
	 *     <li>{@link JWA#ES512}
	 * </ul>
	 *
	 * @param header          The JWS header with an "alg" parameter that
	 *                        matches one of the supported ECDSA algorithms. 
	 *                        Must not be {@code null}.
	 * @param signableContent The content to sign. Must not be {@code null}.
	 * @param privateKey      The private key (D). Must not be {@code null}.
	 *
	 * @return The JSON Web Signature (JWS) bytes, Base64URL-encoded.
	 *
	 * @throws JWSException If signing failed for some reason.
	 */
	public static Base64URL ecdsaSign(final ReadOnlyJWSHeader header,
	                                  final byte[] signableContent,
				          final BigInteger privateKey)
		throws JWSException {
	
		ECDSAParameters initParams = getECDSAParameters(header.getAlgorithm());
		X9ECParameters x9ECParameters = initParams.getX9ECParameters();
		Digest digest = initParams.getDigest();
		
		ECDomainParameters ecParameterSpec = new ECDomainParameters(
							x9ECParameters.getCurve(), 
							x9ECParameters.getG(), 
							x9ECParameters.getN(), 
							x9ECParameters.getH(), 
							x9ECParameters.getSeed());
		
		ECPrivateKeyParameters ecPrivateKeyParameters = 
			new ECPrivateKeyParameters(privateKey, ecParameterSpec);

		digest.update(signableContent, 0, signableContent.length);
		byte[] out = new byte[digest.getDigestSize()];
		/*int result =*/ digest.doFinal(out, 0);

		byte[] sig = doECDSA(ecPrivateKeyParameters, out);

		return Base64URL.encode(sig);
	}
	
	
	/**
	 * Performs the actual ECDSA signing.
	 *
	 * @param ecPrivateKeyParameters The EC private key parameters. Must not
	 *                               be {@code null}.
	 * @param bytes                  The byte array to sign. Must not be 
	 *                               {@code null}.
	 *
	 * @return The ECDSA signture.
	 */
	private static byte[] doECDSA(final ECPrivateKeyParameters ecPrivateKeyParameters, final byte[] bytes) {

		ECDSASigner signer = new ECDSASigner();
		signer.init(true, ecPrivateKeyParameters);
		BigInteger[] res = signer.generateSignature(bytes);
		BigInteger r = res[0];
		BigInteger s = res[1];

		return rs2jwt(r, s);
	}


	/**
	 * Converts the specified big integers to byte arrays and returns their
	 * concatenation.
	 *
	 * @param r The first big integer. Must not be {@code null}.
	 * @param s The second big integer. Must not be {@code null}.
	 *
	 * @return The resulting byte array.
	 */
	private static byte[] rs2jwt(final BigInteger r, final BigInteger s) {
		
		//    System.out.println("R:" + r.toString());
		//    System.out.println("S:" + s.toString());
		
		byte[] rBytes = r.toByteArray();
		//    System.out.println("rBytes.length:" + rBytes.length);
		
		byte[] sBytes = s.toByteArray();
		//    System.out.println("sBytes.length:" + sBytes.length);
		//    StringBuffer sb = new StringBuffer();
		//    for (int i=0; i<rBytes.length;i++) {
		//      sb.append(String.valueOf((int)rBytes[i]));
		//      sb.append(',');
		//    }
		//    System.out.println("Rbytes:" + sb.toString());
		//    sb = new StringBuffer();
		//    for (int i=0; i<sBytes.length;i++) {
		//      sb.append(String.valueOf((int)sBytes[i]));
		//      sb.append(',');
		//    }
		//    System.out.println("Sbytes:" + sb.toString());
		
		byte[] rsBytes = new byte[64];
		
		for (int i=0; i<rsBytes.length; i++) {
			rsBytes[i] = 0;
		}
		
		if (rBytes.length >= 32) {
			System.arraycopy(rBytes, rBytes.length - 32, rsBytes, 0, 32);
		}
		else {
			System.arraycopy(rBytes, 0, rsBytes, 32 - rBytes.length, rBytes.length);
		}
		
		if (sBytes.length >= 32) {
			System.arraycopy(sBytes, sBytes.length - 32, rsBytes, 32, 32);
		}
		else {
			System.arraycopy(sBytes, 0, rsBytes, 64 - sBytes.length, sBytes.length);
		}
		
		return rsBytes;
	}
  
  
  	/**
	 * Verifies an ECDSA-based JSON Web Signature (JWS) using the specified
	 * elliptic curve parameters.
	 *
	 * <p>Supported signature algorithms:
	 *
	 * <ul>
	 *     <li>{@link JWA#ES256} (recommended for JWS implementations)
	 *     <li>{@link JWA#ES384}
	 *     <li>{@link JWA#ES512}
	 * </ul>
	 *
	 * @param header        The JWS header with an "alg" parameter that
	 *                      matches one of the supported ECDSA algorithms.
	 *                      Must not be {@code null}.
	 * @param signedContent The signed content. Must not be {@code null}.
	 * @param signature     The signature to verify. Must not be 
	 *                      {@code null}.
	 * @param x             The x elliptic curve parameter. Must not be 
	 *                      {@code null}.
	 * @param y             The y elliptic curve parameter. Must not be 
	 *                      {@code null}.
	 *
	 * @return {@code true} if the signature is successfully verified, else 
	 *         {@code false}.
	 *
	 * @throws JWSException If verification failed for some reason.
	 */
	public static boolean ecdsaVerify(final ReadOnlyJWSHeader header,
	                                  final byte[] signedContent,
				          final Base64URL signature,
				          final BigInteger x, 
				          final BigInteger y) 
		throws JWSException {

		ECDSAParameters initParams = getECDSAParameters(header.getAlgorithm());
		X9ECParameters x9ECParameters = initParams.getX9ECParameters();
		Digest digest = initParams.getDigest();
		

		byte[] signatureBytes = signature.decode();
		
		byte[] rBytes = new byte[32];
		byte[] sBytes = new byte[32];
		
		try {
			System.arraycopy(signatureBytes, 0, rBytes, 0, 32);
			System.arraycopy(signatureBytes, 32, sBytes, 0, 32);
			
		} catch (Exception e) {
		
			throw new JWSException("Invalid ECDSA signature format: " + e.getMessage(), e);
		}

		BigInteger r = new BigInteger(1, rBytes);
		BigInteger s = new BigInteger(1, sBytes);
		
		
		ECCurve curve = x9ECParameters.getCurve();
		ECPoint qB = curve.createPoint(x, y, false);
		ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
		
		ECDomainParameters ecDomainParameters = new ECDomainParameters(
								curve, 
								x9ECParameters.getG(), 
								x9ECParameters.getN(), 
								x9ECParameters.getH(),
								x9ECParameters.getSeed());
		
		ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
								q, ecDomainParameters);

		ECDSASigner verifier = new ECDSASigner();
		verifier.init(false, ecPublicKeyParameters);
		
		digest.update(signedContent, 0, signedContent.length);
		byte[] out = new byte[digest.getDigestSize()];
		/*int result =*/ digest.doFinal(out, 0);

		return verifier.verifySignature(out, r, s);
	}
	
	
	/**
	 * Prevents instantiation.
	 */
	private JWS() {
	
		// Nothing to do
	}
}
