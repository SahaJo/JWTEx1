package com.deed.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.deed.jwt.config.auth.PrincipalDetails;
import com.deed.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
// 스프링 시큐리티에서  UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 동작을 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter  extends UsernamePasswordAuthenticationFilter{
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username, password 받아서
		try {
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println("input : " + input);
//			}
//			System.out.println(request.getInputStream().toString()); // username, password 담김
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(),	User.class);
			System.out.println("user : " + user);
			System.out.println("1-------------------------------");
			
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			// PrincipalDetailsService의 loadUserByUsername() 함수가  실행됨 // 내 로그인한 정보가 담김
			// 실행된 후 정상이면 authentication이 리턴됨. DB에 있는 username과 password가 일치함
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			// authentication 객체가 session영역에 저장됨. -> 로그인 되었다는 뜻.
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());	// 로그인 정상적으로 완료
			System.out.println("================================");
//			System.out.println("authentication :  " + authentication);
			
			// authentication 객체가 session영역에 저장을 해야하고 그방법이 return해주면됨.
			// 리턴의 이뉴는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
			// 굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session을 넣어줌.
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// 2. 정상인지 로그인시도를 해봄. authenticationManager로 로그인 시도를 하면 
		// PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행됨.
		// 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
		// 4. JWT토큰을 만들어서 응답해주면 됨.
		return null;
	} // attemptAuthentication
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행 됨
	// JWT 토큰을 만들어거 request요청한 사용자에게 JWT토큰을 response 해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println();
		System.out.println("successfulAuthentication 실행됨: 인증이 완료되었음");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// dependency 입력해줘서 가능
		// RSA방식은 아니고 Hash암호방식 
		String jwtToken = JWT.create()
				.withSubject("cos토큰") 		// 토큰이름
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) // 토큰 유지시간
				.withClaim("id", principalDetails.getUser().getUsername())	// 비공개 클레임 아무거나 담아도됨
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));	// secret 값 지정
				// HMAC512 특징은 시크릿 값을 들고 있어야함
		System.out.println("-=------------------------------------");
		System.out.println("jwtToken:::::: " + jwtToken);
																				// Bearer은 반듯이 한칸 뛰어야함
		response.addHeader("Authorization", "Bearer "+jwtToken);
		// 아래 명령어가 있으면 header값이 노출되지 않음
		//		super.successfulAuthentication(request, response, chain, authResult);
		
	}
} // end
