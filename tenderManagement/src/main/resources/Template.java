 RoleModel.java

package com.fresco.tenderManagement.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true)
    private String rolename;
}


UserModel.java
package com.fresco.tenderManagement.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String username;
    private String companyName;

    @Column(unique = true)
    private String email;

    private String password;

    @ManyToOne
    @JoinColumn(name = "role", referencedColumnName = "id")
    private RoleModel role;
}


BiddingModel.java
package com.fresco.tenderManagement.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class BiddingModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true)
    private Integer biddingId;

    private final String projectName = "Metro Phase V 2024";

    private Double bidAmount;
    private Double yearsToComplete;
    private String dateOfBidding;
    private String status = "pending";

    @ManyToOne
    @JoinColumn(name = "bidderId", referencedColumnName = "id")
    private UserModel bidder;
}

RoleRepository.java
package com.fresco.tenderManagement.repository;

import com.fresco.tenderManagement.model.RoleModel;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleModel, Integer> {
    RoleModel findByRolename(String rolename);
}


UserRepository.java
package com.fresco.tenderManagement.repository;

import com.fresco.tenderManagement.model.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserModel, Integer> {
    UserModel findByEmail(String email);
}


BiddingRepository.java
package com.fresco.tenderManagement.repository;

import com.fresco.tenderManagement.model.BiddingModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BiddingRepository extends JpaRepository<BiddingModel, Integer> {
    List<BiddingModel> findByBidAmountGreaterThan(Double bidAmount);
    BiddingModel findByBiddingId(Integer biddingId);
}


LoginDTO.java
package com.fresco.tenderManagement.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginDTO {
    private String email;
    private String password;
}


DataLoader.java
package com.fresco.tenderManagement.configuration;

import com.fresco.tenderManagement.model.*;
import com.fresco.tenderManagement.repository.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private final RoleRepository roleRepo;
    private final UserRepository userRepo;

    public DataLoader(RoleRepository roleRepo, UserRepository userRepo) {
        this.roleRepo = roleRepo;
        this.userRepo = userRepo;
    }

    @Override
    public void run(String... args) {
        RoleModel bidderRole = new RoleModel(null, "BIDDER");
        RoleModel approverRole = new RoleModel(null, "APPROVER");

        roleRepo.save(bidderRole);
        roleRepo.save(approverRole);

        userRepo.save(new UserModel(null, "bidder1", "companyOne", "bidderemail@gmail.com", "bidder123$", bidderRole));
        userRepo.save(new UserModel(null, "bidder2", "companyTwo", "bidderemail2@gmail.com", "bidder789$", bidderRole));
        userRepo.save(new UserModel(null, "approver", "defaultCompany", "approveremail@gmail.com", "approver123$", approverRole));
    }
}


UserService.java
package com.fresco.tenderManagement.service;

import com.fresco.tenderManagement.model.UserModel;
import com.fresco.tenderManagement.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public UserModel findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}


LoginService.java
package com.fresco.tenderManagement.service;

import com.fresco.tenderManagement.model.UserModel;
import com.fresco.tenderManagement.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class LoginService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserModel user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }

        List<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority(user.getRole().getRolename())
        );

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }
}


BiddingService.java
package com.fresco.tenderManagement.service;

import com.fresco.tenderManagement.model.BiddingModel;
import com.fresco.tenderManagement.model.UserModel;
import com.fresco.tenderManagement.repository.BiddingRepository;
import com.fresco.tenderManagement.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class BiddingService {

    @Autowired
    private BiddingRepository biddingRepository;

    @Autowired
    private UserRepository userRepository;

    public BiddingModel addBidding(BiddingModel biddingModel, String userEmail) {
        UserModel bidder = userRepository.findByEmail(userEmail);
        if (bidder == null || !bidder.getRole().getRolename().equals("BIDDER")) {
            throw new RuntimeException("Invalid user or not a bidder");
        }

        // Set required fields
        biddingModel.setBidder(bidder);
        biddingModel.setStatus("pending");
        biddingModel.setDateOfBidding(new SimpleDateFormat("dd/MM/yyyy").format(new Date()));

        return biddingRepository.save(biddingModel);
    }

    public List<BiddingModel> listBiddings(Double minBidAmount) {
        List<BiddingModel> results = biddingRepository.findByBidAmountGreaterThan(minBidAmount);
        if (results.isEmpty()) {
            throw new RuntimeException("no data available");
        }
        return results;
    }

    public BiddingModel updateStatus(Integer id, String status) {
        Optional<BiddingModel> optional = biddingRepository.findById(id);
        if (optional.isEmpty()) {
            throw new RuntimeException("Invalid bidding ID");
        }

        BiddingModel bidding = optional.get();
        bidding.setStatus(status);
        return biddingRepository.save(bidding);
    }

    public String deleteBidding(Integer id, String userEmail) {
        Optional<BiddingModel> optional = biddingRepository.findById(id);
        if (optional.isEmpty()) {
            throw new RuntimeException("not found");
        }

        BiddingModel bidding = optional.get();
        UserModel user = userRepository.findByEmail(userEmail);
        String userRole = user.getRole().getRolename();

        boolean isApprover = userRole.equals("APPROVER");
        boolean isBidderOwner = userRole.equals("BIDDER") && bidding.getBidder().getEmail().equals(userEmail);

        if (!isApprover && !isBidderOwner) {
            throw new SecurityException("you don’t have permission");
        }

        biddingRepository.deleteById(id);
        return "deleted successfully";
    }
}



LoginController.java

package com.fresco.tenderManagement.controller;

import com.fresco.tenderManagement.dto.LoginDTO;
import com.fresco.tenderManagement.security.JWTUtil;
import com.fresco.tenderManagement.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private LoginService loginService;

    @Autowired
    private JWTUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<Object> authenticateUser(@RequestBody LoginDTO loginDTO) {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword())
            );

            UserDetails userDetails = loginService.loadUserByUsername(loginDTO.getEmail());
            String jwt = jwtUtil.generateToken(userDetails);

            Map<String, Object> response = new HashMap<>();
            response.put("jwt", jwt);
            response.put("status", HttpStatus.OK.value());

            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Invalid credentials", HttpStatus.BAD_REQUEST);
        }
    }
}



 BiddingController.java

package com.fresco.tenderManagement.controller;

import com.fresco.tenderManagement.model.BiddingModel;
import com.fresco.tenderManagement.service.BiddingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/bidding")
public class BiddingController {

    @Autowired
    private BiddingService biddingService;

    // Accessible by BIDDER
    @PostMapping("/add")
    public ResponseEntity<?> addBidding(@RequestBody BiddingModel biddingModel, Authentication authentication) {
        try {
            String userEmail = authentication.getName();
            BiddingModel saved = biddingService.addBidding(biddingModel, userEmail);
            return new ResponseEntity<>(saved, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>("Bad Request: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // Accessible by BIDDER and APPROVER
    @GetMapping("/list")
    public ResponseEntity<?> listBiddings(@RequestParam double bidAmount) {
        try {
            List<BiddingModel> bids = biddingService.listBiddings(bidAmount);
            return new ResponseEntity<>(bids, HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>("no data available", HttpStatus.BAD_REQUEST);
        }
    }

    // Accessible by APPROVER
    @PatchMapping("/update/{id}")
    public ResponseEntity<?> updateStatus(@PathVariable Integer id, @RequestBody Map<String, String> req) {
        try {
            BiddingModel updated = biddingService.updateStatus(id, req.get("status"));
            return new ResponseEntity<>(updated, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Bad Request: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // Accessible by APPROVER or BIDDER (if creator)
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteBid(@PathVariable Integer id, Authentication authentication) {
        try {
            String userEmail = authentication.getName();
            String result = biddingService.deleteBidding(id, userEmail);
            return new ResponseEntity<>(result, HttpStatus.NO_CONTENT);
        } catch (SecurityException e) {
            return new ResponseEntity<>("you don’t have permission", HttpStatus.FORBIDDEN);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
}


. JWTUtil.java
package com.fresco.tenderManagement.security;

import com.fresco.tenderManagement.service.UserService;
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
        final Claims claims = getAllClaimsFromToken(token);
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
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
}


AuthenticationFilter.java
package com.fresco.tenderManagement.security;

import com.fresco.tenderManagement.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.*;

import java.io.IOException;

@Component
public class AuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private LoginService loginService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        String username = null;
        String token = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            try {
                username = jwtUtil.getUsernameFromToken(token);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = loginService.loadUserByUsername(username);

            if (jwtUtil.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        chain.doFilter(request, response);
    }
}


SecurityConfiguration.java

package com.fresco.tenderManagement.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationFilter authFilter;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/h2-console/**", "/login");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/bidding/add").hasAuthority("BIDDER")
            .antMatchers("/bidding/update/**", "/bidding/delete/**").hasAuthority("APPROVER")
            .antMatchers("/bidding/list").hasAnyAuthority("BIDDER", "APPROVER")
            .anyRequest().authenticated()
            .and()
            .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // For test/demo only
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}


