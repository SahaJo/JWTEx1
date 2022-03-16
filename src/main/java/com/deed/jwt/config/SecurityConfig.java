package com.deed.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

import com.deed.jwt.config.jwt.JwtAuthenticationFilter;
import com.deed.jwt.config.jwt.JwtAuthorizationFilter;
import com.deed.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends  WebSecurityConfigurerAdapter{
	
	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	// JWT 기본 양식
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // 가장먼저 실행됨
		// security filter가 기본 필터보다 먼저 실행됨
//		http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);  // 시큐리티에 굳이 걸필요 없음
//		http.addFilterAfter(new MyFilter3(), BasicAuthenticationFilter.class);  
		
		http.csrf().disable();			//  기본 로그인 안씀
		// 내서버 버전 session을 사용하지않겠다 
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 
		.and()
		.addFilter(corsFilter)			// @Crossorigin (인증X), 시큐리티 필터에 등록 인증(O)
		.formLogin().disable()		// form 태그 로그인 안씀
		.httpBasic().disable()			// headers -> Authorization : id + pass = http Basic 방식 암호화 노출
														// https 암호화가 되서 날아감  Authorization을 토큰은 노출이돼도 안전함
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager
		.addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)) // AuthenticationManager
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll()
		
		;
		
	} // configure

}
