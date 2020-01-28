package com.springSecurity.config;

import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.springSecurity.security.UserPrincipal;

@Configuration
@EnableJpaAuditing
public class AuditingConfig {

	@Bean
	public AuditorAware<Long> auditorAware() {
		System.out.println("============================Inside AuditorAware");
		return new SpringSecurityAuditAwareImpl();
	}
}

class SpringSecurityAuditAwareImpl implements AuditorAware<Long> {

	@Override
	public Optional<Long> getCurrentAuditor() {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null || !authentication.isAuthenticated()
				|| authentication instanceof AnonymousAuthenticationToken) {
			System.out.println("============================Inside AuditorAware empty"+Optional.empty());
			return Optional.empty();
		}

		UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
		System.out.println("============================Inside AuditorAware Id : "+Optional.ofNullable(principal.getId()));
		return Optional.ofNullable(principal.getId());

	}
}
