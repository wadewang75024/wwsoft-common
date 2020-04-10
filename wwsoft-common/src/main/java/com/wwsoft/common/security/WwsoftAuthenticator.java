package com.wwsoft.common.security;

import java.util.HashMap;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureException;

@AuthenticatorSetup(jwt_key_prefix = "APP_", 
jwt_expiration_min = 3000000, 
jwt_issuer = "wwsoft", jwt_subject = "wwsoft-app", 
jwt_subject_link = "wwsoft-app", 
expected_Claims = { @ExpectedClaim(claim = MyClaim.CLAIM_KEY_BASIC_INFO) })
public class WwsoftAuthenticator extends WwsoftBaseAuthenticator {
	
	private AuthenticatorSetup authenticatorAnnotation;
	
	/**
	 * This private method reads the JWT_KEY from system properties.
	 * @return
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private String getJwtKey() throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return decrypt(System.getProperty(authenticatorAnnotation.jwt_key_prefix() + "JWT_KEY"));
		//return System.getProperty(JWT_KEY);
	} 
	
	/**
	 * This method returns the jti attribute in the given JWT token.  It's used to parse a in-bound token.
	 * @param token
	 * @return
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String getId(String token)
			throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		checkAnnotation();
		return getId(getJwtKey(), token);
	}	
	
	/**
	 * This method returns the claims in the given JWT token.  It's used to parse a in-bound token.
	 * @param token
	 * @return
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public Claims getClaims(String token)
			throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return getClaims(getJwtKey(), token);
	}

	/**
	 * This method is used to add a claim to a JWT token.  It's used when create a JWT token.
	 * @param oldToken
	 * @param field
	 * @param value
	 * @return
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String appendClaim(String oldToken, String field, Object value)
			throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return getNewToken(getJwtKey(), authenticatorAnnotation.jwt_subject(), authenticatorAnnotation.jwt_issuer(),
				authenticatorAnnotation.jwt_expiration_min(), oldToken, field, value);
	}
	
	private void checkAnnotation() {
		Class<?> thisClass = this.getClass();
		authenticatorAnnotation = thisClass.getAnnotation(AuthenticatorSetup.class);
		if (authenticatorAnnotation == null)
			throw new SignatureException("Missing authenticator annotation.");
	}

	/**
	 * This method is used to create a JWT token.
	 * @param userId
	 * @param claims
	 * @return
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String createToken(String userId, boolean subjectLink, HashMap<String, Object> claims) 
			throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {	
		checkAnnotation();
		String subject;
		if (subjectLink)
			subject = authenticatorAnnotation.jwt_subject_link();
		else
			subject = authenticatorAnnotation.jwt_subject();
		return createToken(userId, getJwtKey(), subject, authenticatorAnnotation.jwt_issuer(), 
						   authenticatorAnnotation.jwt_expiration_min(), claims);
	}
	
}
