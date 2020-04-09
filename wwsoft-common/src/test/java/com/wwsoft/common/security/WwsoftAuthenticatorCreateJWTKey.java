package com.wwsoft.common.security;

import org.junit.Before;
import org.junit.Test;

/**
 * This test program can be used to create an encrypted JWT key.  
 * Otherwise, decrypt method will fail if the raw string like the one specified in ORIGINAL_JWT_KEY below.
 * The one below is generated with echo -n "somevalue" | openssl sha512 -hmac "somekey", which is given
 * in "https://stackoverflow.com/questions/33960565/how-to-generate-a-hs512-secret-key-to-use-with-jwt"
 * 
 * @author wang
 *
 */
public class WwsoftAuthenticatorCreateJWTKey {
	
	private WwsoftAuthenticator wwsoftAuthenticator;
	
	@Before
	public void setUp() throws Exception {
		wwsoftAuthenticator = new WwsoftAuthenticator();
		System.setProperty("ORIGINAL_JWT_KEY", "f7a298b19e6d1faeec691c59cbf146437a6cc3235b4fdd61c62aa498c85da410b45c4b701dd9f2d5230fb69cdfe6eb19979c9240b224b56c56949225449f7083");
	}
	
	@Test
	public void createJWTKey() throws Exception {		
		String key = wwsoftAuthenticator.encrypt(System.getProperty("ORIGINAL_JWT_KEY"));
		System.out.println("Created key: " + key);
	}
}
