package com.nyit.Gmail;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.james.jdkim.codec.binary.Base64;

public class TestBodyHash {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		String bodyData = "PGRpdiBkaXI9Imx0ciI-VGVzdCBIZWFkZXJzPC9kaXY-DQo=";
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] bytes = Base64.decodeBase64(bodyData.intern());
		System.out.println(new String(bytes));
		byte[] hash = digest.digest(new String(bytes).getBytes());
		System.out.println("Hash is:" + hash);
		System.out.println("Hash is:" + "SHA-256-" + Base64.encodeBase64String(hash));

	}

}
