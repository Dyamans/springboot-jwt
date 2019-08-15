package com.pats.security.jwtsecurity;

import org.springframework.stereotype.Component;

import com.pats.security.jwtsecurity.model.JwtUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JwtUserValidator {

	private String secret = "youtube";

	public JwtUser validate(String token) {
		
		JwtUser jwtUser = null;
		try {
			Claims body = Jwts.parser().
					 setSigningKey(secret)
	                .parseClaimsJws(token)
	                .getBody();
			
			jwtUser = new JwtUser();
			
			jwtUser.setUserName(body.getSubject());
	        jwtUser.setId(Long.parseLong((String) body.get("userId")));
	        jwtUser.setRole((String) body.get("role"));			
			
		}
		catch (Exception e) {
            System.out.println(e);
        }		
		return jwtUser;		
	}
}
