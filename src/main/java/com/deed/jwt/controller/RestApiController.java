package com.deed.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.deed.jwt.config.auth.PrincipalDetails;
import com.deed.jwt.model.User;
import com.deed.jwt.repository.UserRepository;

//@Crossorigin 로그인이 필요한 인증은 불가능함
@RestController
public class RestApiController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	} // home
	
	@PostMapping("/token")
	public String token() {
		return "<h1>token</h1>";
	} // home
	
	// 추가한 뒤 포스트맨을 열어서 테스트
	@PostMapping("join")
	public String join(@RequestBody User user) {
		System.out.println("회원가입시도 : " + user.getPassword() +" __ " + user.getUsername());
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입 완료";
	}
	
	// user, manager, admin
	@GetMapping("/api/v1/user")
	public String user(Authentication authentication) {
		System.out.println("********Controller-user *****");
		PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication: " + principal.getUsername());
		
		return "user";
	}
	
	// manager, admin
	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	
	// admin
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}
	
} // end 
