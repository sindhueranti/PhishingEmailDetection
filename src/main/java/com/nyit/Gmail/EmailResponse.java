package com.nyit.Gmail;

public class EmailResponse {

	private String isValidDKIM;
	private String isValidDmarc;
	private String isValidSPF;
	private int positivePer;
	private String emailValidationResult;

	public String getIsValidDKIM() {
		return isValidDKIM;
	}

	public void setIsValidDKIM(String isValidDKIM) {
		this.isValidDKIM = isValidDKIM;
	}

	public String getIsValidDmarc() {
		return isValidDmarc;
	}

	public void setIsValidDmarc(String isValidDmarc) {
		this.isValidDmarc = isValidDmarc;
	}

	public String getIsValidSPF() {
		return isValidSPF;
	}

	public void setIsValidSPF(String isValidSPF) {
		this.isValidSPF = isValidSPF;
	}

	public int getPositivePer() {
		return positivePer;
	}

	public void setPositivePer(int positivePer) {
		this.positivePer = positivePer;
	}

	public String getEmailValidationResult() {
		return emailValidationResult;
	}

	public void setEmailValidationResult(String emailValidationResult) {
		this.emailValidationResult = emailValidationResult;
	}

}
