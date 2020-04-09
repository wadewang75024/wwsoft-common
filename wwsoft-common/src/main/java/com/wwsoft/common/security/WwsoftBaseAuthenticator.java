package com.wwsoft.common.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.time.DateUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public abstract class WwsoftBaseAuthenticator {
	
	protected static final String CODE_KEY = "NxKeYz";
	protected static final String DB_KEY = "hrAkNc8sNXa9iNvlRUnr878Zo3";
	protected static final String WWSOFT_CRYPTO_KEY_1894 = CODE_KEY + DB_KEY;
	protected static final String ALGORITHM = "AES";
	protected final static String IGNORE_STRING="test-test-test";
	
	protected static final String INIT_VECTOR = "RandomInitVector"; // 16 bytes IV
	protected static final String UTF_CODING = "UTF-8";
	
	protected static final int TIME_OFFSET = -5;
	
	protected String getId(String key, String token) {
		return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getId();
	}

	protected Claims getClaims(String key, String token) {
		return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
	}
	
	protected String getNewToken(String key, String subject, String issuer, int expiration, String oldToken,
			   String claimKey, Object payLoad) {
		String user = getId(key, oldToken);
		Claims oldClaims = getClaims(key, oldToken);

		Date timeNow = new Date();
		JwtBuilder jwtBuilder = Jwts.builder();
		jwtBuilder.setClaims(oldClaims);
		if (claimKey != null && payLoad != null) {
			jwtBuilder.claim(claimKey, payLoad);
		}
		jwtBuilder.setId(user);
		jwtBuilder.setSubject(subject);
		jwtBuilder.setIssuer(issuer);
		jwtBuilder.setIssuedAt(timeNow);
		jwtBuilder.setNotBefore(DateUtils.addMinutes(timeNow, TIME_OFFSET));
		jwtBuilder.setExpiration(DateUtils.addMinutes(timeNow, expiration));
		return jwtBuilder.signWith(SignatureAlgorithm.HS512, key).compact();
	}
	
	protected String createToken(String id, String key, String subject, String issuer, int minutes,
			HashMap<String, Object> claims) {
		Date timeNow = new Date();
		JwtBuilder jwtBuilder = Jwts.builder();
		jwtBuilder.setId(id);
		jwtBuilder.setSubject(subject);
		jwtBuilder.setIssuer(issuer);
		if (claims != null) {
			Iterator<Entry<String, Object>> it = claims.entrySet().iterator();
			while (it.hasNext()) {
				Entry<String, Object> pair = it.next();
				jwtBuilder.claim(pair.getKey(), pair.getValue());
			}
		}
		jwtBuilder.setIssuedAt(timeNow);
		jwtBuilder.setExpiration(DateUtils.addMinutes(timeNow, minutes));
		return jwtBuilder.signWith(SignatureAlgorithm.HS512, key).compact();
	}

	/**
	 * This method is used to decrypt a JWY key encrypted with the encrypt method.
	 * 
	 * @param encrypted
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	protected String decrypt(String encrypted)
		throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		if (encrypted.equals(IGNORE_STRING)) {// ignore certain
											// encryption for dev env
											// value to reduce setup
			return encrypted;
		}
		IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(UTF_CODING));
		SecretKeySpec skeySpec = new SecretKeySpec(WWSOFT_CRYPTO_KEY_1894.getBytes(UTF_CODING), ALGORITHM);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

		byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
		String result = new String(original);
		System.out.println("result: " + result);
		return result;
	}

	/**
	 * This method is used to encrypt a JWY key in plain text string.
	 * 
	 * @param value
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encrypt(String value)
		throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		if (value.equals(IGNORE_STRING)) {// ignore certain encryption for
										// dev env value to reduce setup
			return value;
		}
		IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(UTF_CODING));
		SecretKeySpec skeySpec = new SecretKeySpec(WWSOFT_CRYPTO_KEY_1894.getBytes(UTF_CODING), ALGORITHM);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		byte[] encrypted = cipher.doFinal(value.getBytes());

		return Base64.encodeBase64String(encrypted);
	}
}
