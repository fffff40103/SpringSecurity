package com.in28minutes.learnspringsecurity;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class SpringSecurityToken {
	
	@GetMapping("/csrf-token")
	public CsrfToken retrieveCSRF(HttpServletRequest request) {
		return (CsrfToken) request.getAttribute("_csrf");
	}
}
