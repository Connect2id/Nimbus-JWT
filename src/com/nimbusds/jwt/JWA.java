package com.nimbusds.jwt;


import java.security.NoSuchAlgorithmException;


/**
 * Enumeration of the supported JSON Web Algorithms (JWA).
 *
 * <p>Based on the JSON Web Algorithms (JWA) specification which enumerates
 * cryptographic algorithms and identifiers to be used with the JSON Web 
 * Signature (JWS) and JSON Web Encryption (JWE) specifications.
 *
 * <p>See <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-01">JWA draft 01</a>.
 *
 * @author Vladimir Dzhuvinov
 * @version 1.9 (2012-04-01)
 */
public enum JWA {


	/**
	 * No algorithm.
	 */
	NONE("none", Type.NONE, Requirement.OPTIONAL),
	

	/**
	 * HMAC signature using SHA-256 hash algorithm (mandatory for all JWT 
	 * implementations).
	 */
	HS256(Type.SIGNATURE, Requirement.MANDATORY),


	/**
	 * HMAC signature using SHA-384 hash algorithm.
	 */
	HS384(Type.SIGNATURE, Requirement.OPTIONAL),


	/**
	 * HMAC signature using SHA-512 hash algorithm.
	 */
	HS512(Type.SIGNATURE, Requirement.OPTIONAL),


	/**
	 * ECDSA signature using P-256 curve and SHA-256 hash algorithm 
	 * (recommended for JWT implementations).
	 */
	ES256(Type.SIGNATURE, Requirement.RECOMMENDED),


	/**
	 * ECDSA signature using P-384 curve and SHA-384 hash algorithm.
	 */
	ES384(Type.SIGNATURE, Requirement.OPTIONAL),


	/**
	 * ECDSA signature using P-521 curve and SHA-512 hash algorithm.
	 */
	ES512(Type.SIGNATURE, Requirement.OPTIONAL),


	/**
	 * RSA signature using SHA-256 hash algorithm (recommended for JWT 
	 * implementations).
	 */
	RS256(Type.SIGNATURE, Requirement.RECOMMENDED),


	/**
	 * RSA signature using SHA-384 hash algorithm.
	 */
	RS384(Type.SIGNATURE, Requirement.OPTIONAL),


	/**
	 * RSA signature using SHA-512 hash algorithm.
	 */
	RS512(Type.SIGNATURE, Requirement.OPTIONAL),


	/**
	 * AES-CBC encryption with 128 bit key size (additional optional 
	 * encryption algorithm).
	 */
	AE128(Type.ENCRYPTION, Requirement.ADDITIONAL),


	/**
	 * AES-CBC encryption with 192 bit key size (additional optional 
	 * encryption algorithm).
	 */
	AE192(Type.ENCRYPTION, Requirement.ADDITIONAL),


	/**
	 * AES-CBC encryption with 256 bit key size (additional optional 
	 * encryption algorithm).
	 */
	AE256(Type.ENCRYPTION, Requirement.ADDITIONAL),


	/**
	 * RSA encryption using RSA-PKCS1-1.5 padding, as defined in RFC 3447 
	 * (mandatory for all JWT implementations).
	 */
	RSA1_5(Type.ENCRYPTION, Requirement.MANDATORY),


	/**
	 * RSA encryption using Optimal Asymmetric Encryption Padding (OAEP), as
	 * defined in RFC 3447.
	 */
	RSA_OAEP("RSA-OAEP", Type.ENCRYPTION, Requirement.OPTIONAL),


	/**
	 * Advanced Encryption Standard (AES) using 128 bit keys in Cipher Block
	 * Chaining mode, as defined in FIPS-197 and NIST-800-38A (mandatory for
	 * all JWT implementations).
	 */
	A128CBC(Type.ENCRYPTION, Requirement.MANDATORY),


	/**
	 * Advanced Encryption Standard (AES) using 128 bit keys in Cipher Block
	 * Chaining mode, as defined in FIPS-197 and NIST-800-38A (additional
	 * optional encryption algorithm).
	 */
	A192CBC(Type.ENCRYPTION, Requirement.ADDITIONAL),


	/**
	 * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
	 * Chaining mode, as defined in FIPS-197 and NIST-800-38A (mandatory for
	 * all JWT implementations).
	 */
	A256CBC(Type.ENCRYPTION, Requirement.MANDATORY),


	/**
	 * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
	 * Chaining mode, as defined in FIPS-197 and NIST-800-38A (additional
	 * optional encryption algorithm).
	 */
	A512CBC(Type.ENCRYPTION, Requirement.ADDITIONAL),


	/**
	 * Advanced Encryption Standard (AES) using 128 bit keys in 
	 * Galois/Counter Mode, as defined in FIPS-197 and NIST-800-38D 
	 * (recommended for all JWT implementations).
	 */
	A128GCM(Type.ENCRYPTION, Requirement.RECOMMENDED),


	/**
	 * Advanced Encryption Standard (AES) using 128 bit keys in 
	 * Galois/Counter Mode, as defined in FIPS-197 and NIST-800-38D 
	 * (additional optional algorithm).
	 */
	A192GCM(Type.ENCRYPTION, Requirement.ADDITIONAL),


	/**
	 * Advanced Encryption Standard (AES) using 256 bit keys in 
	 * Galois/Counter Mode, as defined in FIPS-197 and NIST-800-38D 
	 * (recommended for all JWT implementations).
	 */
	A256GCM(Type.ENCRYPTION, Requirement.RECOMMENDED),


	/**
	 * Advanced Encryption Standard (AES) using 256 bit keys in 
	 * Galois/Counter Mode, as defined in FIPS-197 and NIST-800-38D 
	 * (additional optional algorithm).
	 */
	A512GCM(Type.ENCRYPTION, Requirement.ADDITIONAL);
	

	/**
	 * Enumeration of the JWA algorithm types.
	 */
	public static enum Type {
	
		
		/**
		 * Signature algorithm.
		 */
		SIGNATURE,
		
		
		/**
		 * Encryption algorithm.
		 */
		ENCRYPTION,
		
		
		/**
		 * None.
		 *
		 * <pre>
		 * {"alg":"none"}
		 * </pre>
		 */
		NONE;
	}
	
	
	/**
	 * Enumeration of the JWA requirements.
	 */
	public static enum Requirement {
	
		
		/**
		 * The algorithm is mandatory (MUST) for all implementations.
		 */
		MANDATORY,
		
		
		/**
		 * The algorithm is recommended for all implementations.
		 */
		RECOMMENDED,
		
		
		/**
		 * The algorithm is optional for implementations.
		 */
		OPTIONAL,
		
		
		/**
		 * The algorithm is additional (optional and not explicitly
		 * listed in the JWA specification).
		 */
		ADDITIONAL;
	}
	

	/**
	 * The algorithm type.
	 */
	private Type type;
	
	
	/**
	 * The algorithm name.
	 */
	private String name;


	/**
	 * The algorithm requirement.
	 */
	private Requirement requirement;
	
	
	/**
	 * Gets the algorithm type.
	 *
	 * @return The algorithm type.
	 */
	public Type getType() {
	
		return type;
	}
	

	/**
	 * Gets the algorithm name.
	 *
	 * @return The algorithm name.
	 */
	public String getName() {
	
		return name;
	}
	
	
	/**
	 * Gets the algorithm requirement.
	 *
	 * @return The algorithm requirement.
	 */
	public Requirement getRequirement() {
	
		return requirement;
	}
		
		
	/**
	 * Creates a new JSON Web Algorithm. The algorithm {@link #getName name}
	 * is set to the enum constant name.
	 *
	 * @param type        The algorithm type. Must not be {@code null}.
	 * @param requirement The algorithm requirement. Must not be 
	 *                    {@code null}.
	 */ 
	private JWA(final Type type, final Requirement requirement) {

		name = super.toString();
		
		if (type == null)
			throw new NullPointerException("The algorithm type must not be null");
			
		this.type = type;

		if (requirement == null)
			throw new NullPointerException("The algorithm requirement must not be null");

		this.requirement = requirement;
	}
		

	/**
	 * Creates a new JSON Web Algorithm. This constructor is intended for 
	 * algorithm names that differ from the enum constant.
	 *
	 * @param name        The algorithm name. Must not be {@code null}.
	 * @param type        The algorithm type. Must not be {@code null}.
	 * @param requirement The algorithm requirement. Must not be 
	 *                    {@code null}.
	 */ 
	private JWA(final String name, final Type type, final Requirement requirement) {

		if (name == null)
			throw new NullPointerException("The algorithm name must not be null");

		this.name = name;
		
		if (type == null)
			throw new NullPointerException("The algorithm type must not be null");
			
		this.type = type;

		if (requirement == null)
			throw new NullPointerException("The algorithm requirement must not be null");

		this.requirement = requirement;
	}
		

	/**
	 * Parses the specified JSON Web Algorithm (JWA) string.
	 *
	 * @param name The canonical algorithm name. Must not be {@code null}.
	 *
	 * @return The parsed encryption algorithm.
	 *
	 * @throws NoSuchAlgorithmException If the name is {@code null} 
	 *                                  or doesn't match a supported
	 *                                  algorithm.
	 */
	public static JWA parse(final String name)
		throws NoSuchAlgorithmException {

		// special cases where name differs from enum const
		if (name != null && name.equals("none"))
			return NONE;
		
		if (name != null && name.equals("RSA-OAEP"))
			return RSA_OAEP;

		try {
			return JWA.valueOf(name);

		} catch (NullPointerException e) {

			throw new NoSuchAlgorithmException("No such algorithm: null");

		} catch (IllegalArgumentException e) {

			throw new NoSuchAlgorithmException("No such algorithm: " + name);
		}
	}
}
