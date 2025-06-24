package security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
		
		String authorizationheader =request.getHeader("Authorization");
		String username=null;
		String token=null;
		
		if (authorizationheader!=null && authorizationheader.startsWith("Bearer")) {
			token=authorizationheader.substring(7);
			username=jwtUtil.getUsernameFromToken(token);
		}
		
		if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=this.loginService.loadUserByUsername(username);
			
			if(jwtUtil.validateToken(token, userDetails)) {
				UsernamePasswordAuthenticationToken authToken=
						new UsernamePasswordAuthenticationToken(userDetails,null,  userDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(request, response);
	}
}


//if (authHeader != null && authHeader.startsWith("Bearer ")) {
//    token = authHeader.substring(7);
//    try {
//        username = jwtUtil.getUsernameFromToken(token);
//    } catch (Exception e) {
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//        return;
//    }
//}
//
//if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//    UserDetails userDetails = loginService.loadUserByUsername(username);
//
//    if (jwtUtil.validateToken(token, userDetails)) {
//        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                userDetails, null, userDetails.getAuthorities()
//        );
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//    }
//}
//
//chain.doFilter(request, response);
//}
//}


//String authorizationHeader=request.getHeader("Authorization");
//
//String username=null;
//String token=null;
//
//if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer")) {
//	token=authorizationHeader.substring(7);
//	username=jwtUtil.getUsernameFromToken(token);
//}
//
//if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
//	UserDetails userDetails=this.loginService.loadUserByUsername(username);
//	
//	if(jwtUtil.validateToken(token, userDetails)) {
//		
//		UsernamePasswordAuthenticationToken authToken=
//				new UsernamePasswordAuthenticationToken(userDetails, null,userDetails.getAuthorities());
//		
//		SecurityContextHolder.getContext().setAuthentication(authToken);
//	}
//}
//filterChain.doFilter(request, response);
