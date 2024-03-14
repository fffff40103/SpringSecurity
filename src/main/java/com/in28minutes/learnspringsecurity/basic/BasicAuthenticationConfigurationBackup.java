package com.in28minutes.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


//@Configuration
//@EnableMethodSecurity(jsr250Enabled = true,securedEnabled = true,prePostEnabled = true)
public class BasicAuthenticationConfigurationBackup {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(
				auth->{
					auth
					.requestMatchers("/users").hasRole("USER")
					.requestMatchers("/admin/**").hasRole("ADMIN")
				    .anyRequest().authenticated();
				}
				
				);
		http.sessionManagement(
				session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				);
		//http.formLogin(withDefaults());
		http.httpBasic(withDefaults());
		http.csrf().disable();
		http.headers().frameOptions().sameOrigin();
		return http.build();
	}
	
	/**
	@Bean
	public InMemoryUserDetailsManager createUserDetailsManager() {
		UserDetails user= User.withUsername("user")
		.password("{noop}password")
		.roles("USER")
		.build();
		
		UserDetails admin=User.withUsername("admin")
		.password("{noop}password")
		.roles("ADMIN")
		.build();
		
		return new InMemoryUserDetailsManager(user,admin);
	}
	**/
	@Bean 
	public DataSource dataSource() {
		 return new EmbeddedDatabaseBuilder()
				 .setType(EmbeddedDatabaseType.H2)
				 .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				 .build();
	}
	
	
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		UserDetails user= User.withUsername("scott")
		.password("password")
		.passwordEncoder(str->passwordEncoder().encode(str))
		.roles("USER")
		.build();
		
		UserDetails admin=User.withUsername("admin")
		.password("password")
		.passwordEncoder(str->passwordEncoder().encode(str))
		.roles("ADMIN","USER")
		.build();
		var jdbcUserDeatilManager= new JdbcUserDetailsManager(dataSource);
		jdbcUserDeatilManager.createUser(user);
		jdbcUserDeatilManager.createUser(admin);
		
		return  jdbcUserDeatilManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
}
