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

public class WwsoftAuthenticator extends WwsoftBaseAuthenticator {
	private final static String JWT_SUBJECT_LINK="wwsoft-common-securtiy";
	private final static int JWT_EXPIRATION_MIN=3000000;
	private final static String JWT_ISSUER="wwsoft";
	private final static String JWT_KEY="JWT_KEY";
	
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
		return decrypt(System.getProperty(JWT_KEY));
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
		return getNewToken(getJwtKey(), JWT_SUBJECT_LINK, JWT_ISSUER, JWT_EXPIRATION_MIN, oldToken, field, value);
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
	public String createToken(String userId, HashMap<String, Object> claims) 
			throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {	
		return createToken(userId, getJwtKey(), JWT_SUBJECT_LINK, JWT_ISSUER, JWT_EXPIRATION_MIN, claims);
	}
	
}
