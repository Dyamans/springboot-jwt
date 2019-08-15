package com.pats.security.jwtsecurity;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.pats.security.jwtsecurity.model.JwtUser;
import com.pats.security.jwtsecurity.model.JwtUserAuthenticationToken;
import com.pats.security.jwtsecurity.model.JwtUserDetails;

@Component
public class JwtAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
	
	@Autowired
    private JwtUserValidator validator;
	
	@Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
		
    }
	
	@Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
		
		JwtUserAuthenticationToken userToken = (JwtUserAuthenticationToken) usernamePasswordAuthenticationToken;
		String token = userToken.getToken();
		JwtUser user = validator.validate(token); 
		if(user == null){
			throw new RuntimeException("JWT token is invalid");
		}
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.
				commaSeparatedStringToAuthorityList(user.getRole());
		 
		 
		return new JwtUserDetails(user.getUserName(), user.getId(),
                	token, grantedAuthorities);
	}
	
	@Override
    public boolean supports(Class<?> aClass) {
		return (JwtUserAuthenticationToken.class.isAssignableFrom(aClass));
	}

}
