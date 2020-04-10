package com.wwsoft.common.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Inherited
public @interface AuthenticatorSetup {
	public String 				jwt_key_prefix() 		default "APP_";
	public int 					jwt_expiration_min() 	default 30;
	public String 				jwt_issuer() 			default "wwsoft";
	public String 				jwt_subject() 			default "wwsoft";
	public String 				jwt_subject_link()		default "wwsoft";
	public ExpectedClaim[]		expected_Claims()		default {};
}
