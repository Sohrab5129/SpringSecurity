package com.springSecurity.controller;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.springSecurity.config.AuditingConfig;
import com.springSecurity.exception.AppException;
import com.springSecurity.model.Role;
import com.springSecurity.model.RoleName;
import com.springSecurity.model.User;
import com.springSecurity.payload.ApiResponse;
import com.springSecurity.payload.JwtAuthenticationResponse;
import com.springSecurity.payload.LoginRequest;
import com.springSecurity.payload.SignUpRequest;
import com.springSecurity.repository.RoleRepository;
import com.springSecurity.repository.UserRepository;
import com.springSecurity.security.JwtTokenProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private static final Logger log = LoggerFactory.getLogger(AuthController.class);

	@Value("${app.jwtSecret}")
	private String jwtSecret;

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	JwtTokenProvider tokenProvider;

	@Autowired
	UserDetailsService service;

	@Autowired
	AuditingConfig conf;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		log.info("Inside authenticateUser");
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsernameOrEmail(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = tokenProvider.generateToken(authentication);

		System.out.println("jwt : " + jwt);

		// generate token using UserDetailsService
		UserDetails details = service.loadUserByUsername(loginRequest.getUsernameOrEmail());

		String token = generateToken(details);
		System.out.println("token : " + token);

		Function<Claims, Date> calimsResolverDate = Claims::getExpiration;
		Date d = calimsResolverDate
				.apply(Jwts.parser().setSigningKey("SohrabShah@786786!@#$%^&*()_+").parseClaimsJws(token).getBody());
		System.out.println("d : " + d);

		Function<Claims, String> calimsResolverSubject = Claims::getSubject;
		String sub = calimsResolverSubject
				.apply(Jwts.parser().setSigningKey("SohrabShah@786786!@#$%^&*()_+").parseClaimsJws(token).getBody());
		System.out.println("sub : " + sub);

		System.out.println("Expiration token : " + d.before(new Date()));

		System.out.println("conf.auditorAware() : " + conf.auditorAware().getCurrentAuditor().get());

		// End generate token using UserDetailsService

		return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
	}

	private String generateToken(UserDetails details) {

		Map<String, Object> claims = new HashMap<>();
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + 604800000);

		return Jwts.builder().setClaims(claims).setSubject(details.getUsername()).setIssuedAt(new Date())
				.setExpiration(expiryDate).signWith(SignatureAlgorithm.HS256, jwtSecret).compact();
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {

		log.info("Inside registerUser");
		
		ArrayList<String> ste=null;
		Object[] list=new Object[10];
		list=Arrays.copyOf(list, list.length*2);
		
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {

			return new ResponseEntity(new ApiResponse(false, "Username is already taken!"), HttpStatus.BAD_REQUEST);
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return new ResponseEntity(new ApiResponse(false, "Email Address already in use!"), HttpStatus.BAD_REQUEST);
		}

		// Creating user's account
		User user = new User(signUpRequest.getName(), signUpRequest.getUsername(), signUpRequest.getEmail(),
				signUpRequest.getPassword());

		user.setPassword(passwordEncoder.encode(user.getPassword()));

		Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
				.orElseThrow(() -> new AppException("User Role not set."));

		user.setRoles(Collections.singleton(userRole));

		User result = userRepository.save(user);

		URI location = ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users/{username}")
				.buildAndExpand(result.getUsername()).toUri();

		return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));
	}

}
