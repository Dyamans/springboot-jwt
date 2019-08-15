package com.pats.security.jwtsecurity;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import com.pats.security.jwtsecurity.model.JwtUserAuthenticationToken;

public class JwtAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter{

	public JwtAuthenticationTokenFilter() {
		super("/rest/**");		
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest arg0,
			HttpServletResponse arg1) throws AuthenticationException,
			IOException, ServletException {
		
		String header = arg0.getHeader("Authorisation");
		
		if (header == null || !header.startsWith("Token ")) {
            throw new RuntimeException("JWT Token is missing");
        }	
		
		String authenticationToken = header.substring(6);		
		
		JwtUserAuthenticationToken token = new JwtUserAuthenticationToken(authenticationToken);
		
        return getAuthenticationManager().authenticate(token);
	}
	
	 @Override
	 protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
	      super.successfulAuthentication(request, response, chain, authResult);
	      chain.doFilter(request, response);
	 }

}
