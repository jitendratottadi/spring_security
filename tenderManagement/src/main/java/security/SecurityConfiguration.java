package security;

import org.springframework.beans.factory.annotation.Autowired; 
import org.springframework.context.annotation.*;
import org.springframework.http.HttpStatus; 
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import service.LoginService;

@EnableWebSecurity
@Configuration public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


	@Autowired
	private AuthenticationFilter authFilter;
	
	@Autowired
	private LoginService loginService;

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/h2-console/**", "/login");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
		.authorizeRequests()
		.requestMatchers("/bidding/add").hasAuthority("BIDDER")
		.requestMatchers("/bidding/update/**", "/bidding/delete/**").hasAuthority("APPROVER")
		.requestMatchers("/bidding/list").hasAnyAuthority("BIDDER", "APPROVER")
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