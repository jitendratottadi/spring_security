package service;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import model.UserModel;
import repository.UserRepository;

@Service
public class LoginService implements UserDetailsService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private UserDetails userDetails;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		UserModel user=userRepository.findByEmail(email);
		
		if(user==null) {
			throw new UsernameNotFoundException("User not found with email:"+email);
		}
		
		return buildUserForAuthentication(user);
	}

	private UserDetails buildUserForAuthentication(UserModel user) {
		// TODO Auto-generated method stub
		
		List<GrantedAuthority> authorities=Collections.singletonList(
				new SimpleGrantedAuthority(user.getRole().getRolename()));
		
		return new org.springframework.security.core.userdetails.User(user.getEmail(),
				user.getPassword(),authorities);
	}



}
