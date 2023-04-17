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
	public ResponseEntity<Object> isValidEmail(
			@RequestParam(value = "emailId", required = false, defaultValue = "dangereliminated@gmail.com") String emailId) {
		try {
			emailResponse = GMail.validateEmail(emailId);
			return new ResponseEntity<>(emailResponse, HttpStatus.OK);
		} catch (IndexOutOfBoundsException e) {
			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}catch (RuntimeException e) {
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

}
