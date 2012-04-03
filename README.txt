Nimbus-JWT

README

Nimbus JWT is a JSON Web Token (JWT) implementation for Java with support for 
signatures (JWS), encryption (JWE) and web keys (JWK). 

JSON Web Token (JWT) is a means of representing claims to be transferred between
two parties. The claims in a JWT are encoded as a JSON object that may be 
digitally signed using JSON Web Signature (JWS) and/or encrypted using JSON Web 
Encryption (JWE).

The suggested pronunciation of JWT is the same as the English word "jot".

This package implements the following IETF drafts:

	* JWT draft 08
	* JWA draft 01
	* JWS draft 01
	* JWE draft 01
	* JWK draft 01 

This package started as a fork of the JWT class from the OpenInfoCard project.

Dependencies:

	* The BouncyCastle.org cryptography provider for Java.
	* Apache Commons Codec for Base64 and Base64URL encoding and decoding.
	* JSON Smart for highly efficient parsing and serialisation of JSON. 
