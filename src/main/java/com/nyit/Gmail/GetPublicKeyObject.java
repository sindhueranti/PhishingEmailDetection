package com.nyit.Gmail;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;



public class GetPublicKeyObject {

	public static void main(String[] args) {

		PublicKey pubKey = null;
		try {
			String publicK = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8JxVBMLHZRj1WvIMSHApRY3DraE/EiFiR6IMAlDq9GAnrVy0tDQyBND1G8+1fy5RwssQ9DgfNe7rImwxabWfWxJ1LSmo/DzEdOHOJNQiP/nw7MdmGu+R9hEvBeGRQ";
			byte[] publicBytes = Base64.getDecoder().decode(publicK);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			pubKey = keyFactory.generatePublic(keySpec);
			System.out.println("Key Generated");
		} catch (Exception ex) {
			ex.printStackTrace();
		}

	}

}
