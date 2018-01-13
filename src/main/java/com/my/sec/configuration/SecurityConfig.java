package com.my.sec.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	public void configureAuth(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
				.withUser("petar")
				.password("petar")
				.roles("ADMIN")
			.and()
				.withUser("dan")
				.password("dan")
				.roles("USER");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated()
				.and()
				.formLogin()
					.loginPage("/login")
					.permitAll()
					.and()
				.logout()
					.logoutSuccessUrl("/login?logout")
					.permitAll();
	}
	
	

}
