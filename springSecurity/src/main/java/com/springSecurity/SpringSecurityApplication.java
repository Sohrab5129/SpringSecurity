package com.springSecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.convert.threeten.Jsr310JpaConverters;

@SpringBootApplication
@EntityScan(basePackageClasses = {
		SpringSecurityApplication.class,
		Jsr310JpaConverters.class
})
public class SpringSecurityApplication {

	public static void main(String[] args) {
		System.out.println("Inside main method");
		SpringApplication.run(SpringSecurityApplication.class, args);
	}
	
//	@PostConstruct
//	void init() {
//		System.out.println("Inside init method");
//		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
//	}

}
