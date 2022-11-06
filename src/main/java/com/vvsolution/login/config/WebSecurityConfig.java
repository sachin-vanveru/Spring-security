package com.vvsolution.login.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.vvsolution.login.model.Users;

@Configuration
public class WebSecurityConfig {
	@Bean
	public UserDetailsService userDetailsService() {
		System.out.println("in userDetailsServicess");
		System.out.println("----"+planpasswordEncoder());
		return new UserDetailsServiceImpl();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public PasswordEncoder planpasswordEncoder() {
	    return PlainTextPasswordEncoder.getInstance();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		System.out.println("in authenticationProvider");
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
//		authProvider.setPasswordEncoder(planpasswordEncoder());
		authProvider.setPasswordEncoder(passwordEncoder());
		
		return authProvider;

	}
	  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		  System.out.println("AuthenticationManagerBuilder:----");
	        auth.authenticationProvider(authenticationProvider());
	      System.out.println(auth.userDetailsService(userDetailsService()));  
	    }
	 

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		System.out.println("in security filter");
		http.authorizeRequests().antMatchers("/").hasAnyAuthority("USER", "CREATOR", "EDITOR", "ADMIN")
				.antMatchers("/new").hasAnyAuthority("ADMIN", "CREATOR").antMatchers("/edit/**")
				.hasAnyAuthority("ADMIN", "EDITOR").antMatchers("/delete/**").hasAnyAuthority("ADMIN").anyRequest()
				.authenticated().and().formLogin().permitAll().and().logout().permitAll().and().exceptionHandling()
				.accessDeniedPage("/403");

		return http.build();
	}

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		
//		http.authorizeRequests()
//		.antMatchers("/").hasAnyAuthority("USER","CREATOR","EDITOR","ADMIN")
//		.antMatchers("/new").hasAnyAuthority("ADMIN","CREATOR")
//		.antMatchers("/edit/**").hasAnyAuthority("ADMIN","EDITOR")
//		.antMatchers("/delete/**").hasAnyAuthority("ADMIN")
//		.anyRequest().authenticated()
//		.and()
//		.formLogin().permitAll()
//		.and()
//		.logout().permitAll()
//		.and()
//		.exceptionHandling().accessDeniedPage("/403")
//		;
//	}

}
