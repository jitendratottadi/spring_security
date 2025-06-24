package security;
//
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.function.Function;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import service.UserService;
//
//
//
//@Component
//public class JWTUtil {
//
//    private static final long serialVersionUID = 654352132132L;
//    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60; // 5 hours
//
//    private final String secretKey = "randomkey123";
//
//    @Autowired
//    private UserService userService;
//
//    public String getUsernameFromToken(String token) {
//        return getClaimFromToken(token, Claims::getSubject);
//    }
//
//    public Date getExpirationDateFromToken(String token) {
//        return getClaimFromToken(token, Claims::getExpiration);
//    }
//
//    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = getAllClaimsFromToken(token);
//        return claimsResolver.apply(claims);
//    }
//
//    private Claims getAllClaimsFromToken(String token) {
//        return Jwts.parser()
//        		.setSigningKey(secretKey)
//        		.build()
//        		.parseSignedClaims(token)
//        		.getPayload();
//    }
//
//    private Boolean isTokenExpired(String token) {
//        final Date expiration = getExpirationDateFromToken(token);
//        return expiration.before(new Date());
//    }
//
//    public String generateToken(String username) {
//        Map<String, Object> claims = new HashMap<>();
//        //claims.put("roles", userDetails.getAuthorities());
//        return Jwts.builder()
//                .claims(claims)
//                .subject(username)
//                .issuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
//                //.signWith(SignatureAlgorithm.HS512, secretKey)
//                .signWith(SignatureAlgorithm.HS512, secretKey)
//                .compact();
//    }
//
////    private String doGenerateToken( String subject) {
////    	Map<String, Object> claims=new HashMap<>();
////        return Jwts.builder()
////                .claims(claims)
////                .subject(subject)
////                .issuedAt(new Date(System.currentTimeMillis()))
////                .expiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
////                .signWith(SignatureAlgorithm.HS512, secretKey)
////                .compact();
////    }
//
//    public Boolean validateToken(String token, UserDetails userDetails) {
//        final String username = getUsernameFromToken(token);
//        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
//    }
//}

import service.UserService;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;

@Component
public class JWTUtil {

	public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
	private final String secretKey = "randomkey123"; // Ideally load from properties

	@Autowired
	private UserService userService;

	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(token)
				.getBody();
	}

	private Boolean isTokenExpired(String token) {
		return getExpirationDateFromToken(token).before(new Date());
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("roles", userDetails.getAuthorities());
		return doGenerateToken(claims, userDetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {
		return Jwts.builder()
				.claims()
				.add(claims)
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
				.and()
				.signWith(SignatureAlgorithm.HS512, secretKey)
				.compact();
	}
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
	}
}