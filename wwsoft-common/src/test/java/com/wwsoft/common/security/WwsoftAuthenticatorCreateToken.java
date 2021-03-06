package com.wwsoft.common.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

/**
 * This test program uses the JWT key generated with WwsoftAuthenticatorCreateJWTKey test program to
 * create a JWT token. The JWT_KEY below is the output from WwsoftAuthenticatorCreateJWTKey.
 * @author wang
 *
 */
public class WwsoftAuthenticatorCreateToken {
	
	private WwsoftAuthenticator wwsoftAuthenticator;
	
	@Before
	public void setUp() throws Exception {
		wwsoftAuthenticator = new WwsoftAuthenticator();
		System.setProperty("APP_JWT_KEY", "/7UzrtXTov8TQU4UIh4usWBKlV2jfv/9N3eshGDSHbWTHiFvJPrt18bIKNU0uyjGhNSJMx0XZEdpz5LitNNqIes2r4pBP9rDZdstJG7syqIhYTLoKbVNB3s8OAOpf9kc5wVCEK9KmWmqNJmfQMyzgnpvIS5PCl1HtuY7BycKvBLBojcyi+RXSxwWE/zNXJld");
	}
	
	@Test
	public void testCreateToken() throws Exception {		
		String token = wwsoftAuthenticator.createToken("wwang", true, null);
		token = wwsoftAuthenticator.appendClaim(token, MyClaim.CLAIM_KEY_ROLE.getEclaimValue(), "Test");
		token = wwsoftAuthenticator.appendClaim(token, MyClaim.CLAIM_KEY_BASIC_INFO.getEclaimValue(), getBasicInfo("HY"));
		
		System.out.println("Created token: " + token);
		
	}
	
	/**
	 * 
	 * @param chainCode
	 * @return
	 */
	private HashMap<String, HashMap<String, List<String>>> getBasicInfo(String chainCode) {
		HashMap<String, HashMap<String, List<String>>> basicInfo = new HashMap();
		HashMap<String, List<String>> pids = new HashMap();
		List<String> pidList = new ArrayList();
		pidList.add("prop1");
		pidList.add("prop2");
		pidList.add("prop3");
		pids.put("HY", pidList);
		basicInfo.put(chainCode, pids);
		return basicInfo;
	}
	
}
