package com.wwsoft.common.security;

import java.util.HashMap;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import io.jsonwebtoken.Claims;

/**
 * This test program shows how to use the JWT token generated by WwsoftAuthenticatorCreateToken.
 * This token is given as "Authorization" and its values is the output from WwsoftAuthenticatorCreateToken.
 * Note it also uses the same JWT_KEY generated by WwsoftAuthenticatorCreateJWTKey.
 * @author wang
 *
 */
public class WwsoftAuthenticatorUseToken {
	private WwsoftAuthenticator wwsoftAuthenticator;
	
	@Before
	public void setUp() throws Exception {
		wwsoftAuthenticator = new WwsoftAuthenticator();
		System.setProperty("APP_JWT_KEY", "/7UzrtXTov8TQU4UIh4usWBKlV2jfv/9N3eshGDSHbWTHiFvJPrt18bIKNU0uyjGhNSJMx0XZEdpz5LitNNqIes2r4pBP9rDZdstJG7syqIhYTLoKbVNB3s8OAOpf9kc5wVCEK9KmWmqNJmfQMyzgnpvIS5PCl1HtuY7BycKvBLBojcyi+RXSxwWE/zNXJld");
		System.setProperty("Authorization", "eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiJ3d2FuZyIsInN1YiI6Ind3c29mdC1jb21tb24tc2VjdXJ0aXkiLCJpc3MiOiJ3d3NvZnQiLCJpYXQiOjE1ODY0Njk4OTgsImV4cCI6MTc2NjQ2OTg5OCwicm9sZSI6IlRlc3QiLCJuYmYiOjE1ODY0Njk1OTgsImJhc2ljX2luZm8iOnsiSFkiOnsiSFkiOlsicHJvcDEiLCJwcm9wMiIsInByb3AzIl19fX0.FkKeuurJ87D33C0wQh3WtfdfNuqmRZzoMVnxhl00oD3Cw_CoS4l4kyq9IpZD0KJyZOc5c7fK7IPUIk8RpTt_uA");
	}
	
	@Test
	public void testCreateToken() throws Exception {		
		String token = System.getProperty("Authorization");
		String id = wwsoftAuthenticator.getId(token);
		System.out.println("id: " + id);
		
		Claims claims = wwsoftAuthenticator.getClaims(token);

		HashMap<String, HashMap<String, List<String>>> claimsData = (HashMap<String, HashMap<String, List<String>>>) claims
				.get(MyClaim.CLAIM_KEY_BASIC_INFO.getEclaimValue());
		
		String chainCode = claimsData.keySet().iterator().next();
		System.out.println("chainCode: " + chainCode);
		HashMap<String, List<String>> brandPids =  claimsData.get(chainCode);
		String brand = brandPids.keySet().iterator().next();
		
		List<String> pids = brandPids.get(brand);
		pids.forEach(pid -> System.out.println(pid) );
	}
}
