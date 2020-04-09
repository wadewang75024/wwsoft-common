package com.wwsoft.common.security;

public enum MyClaim {
	CLAIM_KEY_ROLE("role"),
	CLAIM_KEY_CHAIN("chain"),
	CLAIM_KEY_BRAND("brand"),
	CLAIM_KEY_PID("pid"),
	FILE_NAME_CLAIM("fileName"),
	CLAIM_KEY_BASIC_INFO("basic_info");
	
	protected String claimValue;
	
	private MyClaim(String claimValue) {
		this.claimValue = claimValue;
	}
	
	public String getEclaimValue(){
		return claimValue;
	}
}
