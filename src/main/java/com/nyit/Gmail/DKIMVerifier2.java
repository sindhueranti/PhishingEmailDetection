package com.nyit.Gmail;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DKIMVerifier2 {

    public static boolean verify(String publicKeyString, byte[] message, String signature) {
        try {
            // Decode the public key from the base64-encoded string
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // Get the DKIM signature bytes
            byte[] signatureBytes = Base64.getDecoder().decode(signature);

            // Get the signing algorithm from the DKIM signature header
            String signingAlgorithm = signature.split(";")[1].split("=")[1];

            // Create a signature instance using the signing algorithm
            Signature verifier = Signature.getInstance(signingAlgorithm);

            // Initialize the signature instance with the public key
            verifier.initVerify(publicKey);

            // Update the signature instance with the message bytes
            verifier.update(message);

            // Verify the signature
            return verifier.verify(signatureBytes);
        } catch (Exception e) {
            // Handle exception
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        // The public key string from the DKIM TXT record
    	String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8JxVBMLHZRj1WvIMSHApRY3DraE/EiFiR6IMAlDq9GAnrVy0tDQyBND1G8+1fy5RwssQ9DgfNe7rImwxabWfWxJ1LSmo/DzEdOHOJNQiP/nw7MdmGu+R9hEvBeGRQAmn1jkO46KIw/p2lGvmPSe3+AVD+XyaXZ4vJGTZKFUCnoctAVUyHjSDT7KnEsaiND2rVsDvyisJUAH+EyRfmHSBwfJVHAdJ9oD8cn9NjIun/EHLSIwhCxXmLJlaJeNAFtcGeD2aRGbHaS7M6aTFP+qk4f2ucRx31cyCxbu50CDVfU+d4JkIDNBFDiV+MIpaDFXIf11bGoS08oBBQiyPXgX0wIDAQAB";

        // The raw message bytes
        byte[] message = "This is a test message".getBytes();

        // The DKIM signature header
        String signature = "v=1; a=rsa-sha256; c=relaxed/relaxed;        d=gmail.com; s=20210112; t=1679682507;        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject         :date:message-id:reply-to;        bh=q16ZCFBaW1Vng3M4/JWm/RhAmuiGEBHCG4UKRh5Y9OQ=;        b=DXaz0mC+X6WC0lpXQerkbZYVE2raC6Vi6NAOBgfCLU029tLJc9uKUpfvMNwj9oRVAeQI6QL4VWmRAfCatQInv+bsV9m83Be1MwhuFnoI2W2nu4BmRDqZxyLLxX9qQW/wMoNjp3BfXMOrbIdSSWBtGDH0dEKxSjfIjW8DnDhPiJJdSDTcGurfTCicHa4SafYJu2PxJOPf5jSkvgsQimmggkZtocqSnZtirnggXk+Qw1YO0fg0yM1Qq/2MiY/Zel0nMsdmXKiciTKEwOGV/GZrZ/xQM/UlBwYU6k4Ydj0bDhw17gyQdpphZkviqpNP0/cofGjRwzNgzGX82s3R2PnGkQ==";

        boolean result = verify(publicKey, message, signature.split("b=")[1]);
        if (result) {
            System.out.println("DKIM signature is valid");
        } else {
            System.out.println("DKIM signature is not valid");
        }
    }
}
