package com.nyit.Gmail;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhishingEmailDetection {
	
	private EmailResponse emailResponse = new EmailResponse();
	
	@GetMapping(value = "/PhishingEmailDetection")
	public ResponseEntity<Object> isValidEmail(@RequestParam(value = "emailId", required = false, defaultValue = "dangereliminated@gmail.com") String emailId) { 
		emailResponse = GMail.validateEmail(emailId);
		return new ResponseEntity<>(emailResponse, HttpStatus.OK);
	}

}
