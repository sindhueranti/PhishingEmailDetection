package com.nyit.Gmail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.api.services.gmail.model.Message;

import io.restassured.path.json.JsonPath;

public class BuildMessageHash {

	public static void main(String[] args) {

		String dkimSignature = "v=1; a=rsa-sha256; c=relaxed/relaxed;        d=nyit.edu; s=google; t=1679956087;        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject         :date:message-id:reply-to;        bh=Ki2uJWkSH103C10Kj1bJx0G+BVr6m0yr/R4PjzqnhkU=;        b=LIzMkSoN77uAFgR/H/yz0JVKFcKFj7wv5CQ7PPKvXFWVrIvx62xCYGs8Djy2rhSYEx         vw1R3VlqERip388piXwk3FDdSYPZ2UtToZFZBTwXxTFErgTwFBpxeVeOjb+XDqPNs1s0         ZGK6NOkw47r33KClGE6qD1j7nrQoW2Ji7IRpcV+bY7Ner2pUSfU7MWKBIGvct5Oz/ios         axng0csVZbkPhiDXcOphBzrwrKF26IWwhT4Q08A36X9TbSNLT30gSzuPsDZCqSKR74UQ         QW1cFXr5mKIDZUfToMdB2P2+HS5PwB4EWPQ14OgC2nfCDLJ0nO69ezbRTigAn6BBGJ+M         jdJg==";
		Message message = new Message();
		;
		buildMessage(dkimSignature, message);

	}

	public static String buildMessage(String dkimSignature, Message message) {

		String[] dkimParts = dkimSignature.split("; ");
		String header = "";
		for (String part : dkimParts) {
			if (part.trim().startsWith("h=")) {
				header = part.split("=")[1];
			}
		}
		;
		System.out.println("Header is:" + header);
		String[] headers = header.split(":");
		System.out.println("Headers: " + Arrays.toString(headers));
		List<String> messageHeaderList = new ArrayList();
		JsonPath jp = new JsonPath(message.toString());
		for (String headerValues : headers) {
			String headerValue = "";
			if ("to".equalsIgnoreCase(headerValues))
				headerValue = jp.getString("payload.headers.find { it.name == 'to'}.value");

			messageHeaderList.add(headerValues + ":" + headerValue.trim());

		}
		;
		System.out.println(Arrays.toString(messageHeaderList.toArray()));
		String dkimhash = "";
		return dkimhash;
	}

}
