package security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import service.LoginService;

public class AuthenticationFilter extends OncePerRequestFilter{
	
	@Autowired
	private JWTUtil jwtUtil;

	@Autowired
	private LoginService loginService;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		final String authorizationHeader=request.getHeader("Authorization");
		
		String username=null;
		String jwt=null;
		
		if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer")) {
			jwt=authorizationHeader.substring(7);
			username=JWTUtil.getUsernameFromToken(jwt);
		}
		
		if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=this.loginService.loa
		}
	}
	
	

}
