package com.nyit.Gmail;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude = {org.springframework.boot.autoconfigure.gson.GsonAutoConfiguration.class, org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class})
public class PhishingEmailDetectionApplication {

	public static void main(String[] args) {
		SpringApplication.run(PhishingEmailDetectionApplication.class, args);
	}

}
