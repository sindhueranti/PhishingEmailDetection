package com.nyit.Gmail;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
//import java.util.Base64;

import org.apache.james.jdkim.codec.binary.Base64;

import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePart;

public class CalculateBodyHash {
	
	public static String calculateBodyHash(Message message) throws NoSuchAlgorithmException, IOException {
	    MessagePart payload = message.getPayload();
	    String mimeType = payload.getMimeType();
	    if (mimeType.startsWith("multipart/")) {
	        for (MessagePart part : payload.getParts()) {
	            String partMimeType = part.getMimeType();
	            if (partMimeType.startsWith("text/") || partMimeType.startsWith("message/")) {
	                return calculateBodyHash(new Message().setPayload(part));
	            }
	        }
	        throw new RuntimeException("No text or message part found in multipart message");
	    } else {
	        MessagePart body = payload;
	        if (!mimeType.startsWith("text/")) {
	            String bodyAttachmentId = body.getBody().getAttachmentId();
	            //body = message.getPayload().getBody().getAttachment.stream().filter(attachment -> bodyAttachmentId.equals(attachment.getBody().getAttachmentId())).findFirst().orElse(body);
	        }
	        MessageDigest digest = MessageDigest.getInstance("SHA-256");
	        String bodyData = body.getBody().getData();
	        byte[] bytes = Base64.decodeBase64(bodyData);
	        System.out.println(new String(bytes));
	        byte[] hash = digest.digest(bytes);
	        System.out.println("Hash is:"+hash);
	        System.out.println("Hash is:"+"SHA-256-" + Base64.encodeBase64String(hash));
	        return "SHA-256-" + Base64.encodeBase64String(hash).toLowerCase();
	    }
	}


}
