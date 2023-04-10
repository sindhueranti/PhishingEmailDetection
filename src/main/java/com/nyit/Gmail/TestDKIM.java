package com.nyit.Gmail;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestDKIM {
    public static void main(String[] args) throws Exception {
        // Load the message to be verified
        byte[] messageBytes; // load the message as a byte array

        // Load the DKIM signature as a byte array
        byte[] signatureBytes; // load the DKIM signature as a byte array

        // Load the public key from a file or from a string
        byte[] publicKeyBytes; // load the public key as a byte array
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Verify the DKIM signature using the public key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(messageBytes);
        boolean verified = signature.verify(Base64.getDecoder().decode(signatureBytes));

        if (verified) {
            System.out.println("The DKIM signature is valid.");
        } else {
            System.out.println("The DKIM signature is invalid.");
        }
    }
}

