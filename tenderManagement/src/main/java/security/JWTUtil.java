package security;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;

@Component
public class JWTUtil {
	
	private static final long serialVersionUID=1111111114;
	public static final long JWT_TOKEN_VALIDITY=5*60*60;
	
	private final String secretKey="randomekey123";
	
	
	public String getUsernameFromtoken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}
	
	
	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}
	

	private Date getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims=getAllClaimsFromToken(token);
		// TODO Auto-generated method stub
		return claimsResolver.apply(claims);
	}




	public static String generateToken(UserDetails userDetails) {
		// TODO Auto-generated method stub
		return null;
	}

}
