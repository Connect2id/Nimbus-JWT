/**
 * JSON Web Token (JWT) implementation for Java with support for signatures 
 * (JWS), encryption (JWE) and web keys (JWK).
 *
 * <p>JSON Web Token (JWT) is a means of representing claims to be transferred 
 * between two parties.  The claims in a JWT are encoded as a JSON object that 
 * may be digitally signed using JSON Web Signature (JWS) and/or encrypted using
 * JSON Web Encryption (JWE).
 *
 * <p>The suggested pronunciation of JWT is the same as the English word "jot".
 *
 * <p>This package implements the following IETF drafts:
 * 
 * <ul>
 *     <li><a href="http://tools.ietf.org/html/draft-jones-json-web-token-08">JWT draft 08</a>
 *     <li><a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-01">JWA draft 01</a>
 *     <li><a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-01">JWS draft 01</a>
 *     <li><a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-01">JWE draft 01</a>
 *     <li><a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-key-01">JWK draft 01</a>
 * </ul>
 * 
 * <p>This package started as a fork of the JWT class from the
 * <a href="http://code.google.com/p/openinfocard/">OpenInfoCard</a> project.
 *
 * <p>Dependencies:
 *
 * <ul>
 *     <li>The BouncyCastle.org cryptography provider for Java.
 *     <li>Apache Commons Codec for Base64 and Base64URL encoding and decoding.
 *     <li>JSON Smart for highly efficient parsing and serialisation of JSON.
 * </ul>
 *
 * @version 1.10 (2012-04-03)
 */
package com.nimbusds.jwt;
