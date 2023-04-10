package com.nyit.Gmail;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.mail.internet.MimeMessage;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.james.jdkim.codec.binary.Base64;

public class DKIMValidator {
    public static boolean validateDKIM(MimeMessage message) throws Exception {
        String domain = message.getHeader("DomainKey-Domain", ",");
        String selector = message.getHeader("DomainKey-Signature", ",").split(";")[1].trim().split("=")[1];
        String signature = message.getHeader("DomainKey-Signature", ",").split(";")[2].trim().split("=")[1];

        String record = getDNSRecord(selector, "_domainkey." + domain, "txt");
        String publicKey = extractPublicKey(record);

        return verifyDKIM(signature, publicKey, message);
    }

    private static String getDNSRecord(String recordName, String domain, String type) throws Exception {
        String record = null;
        DirContext dirContext = new InitialDirContext();
        Attributes attributes = dirContext.getAttributes("dns://" + domain, new String[] { "TXT" });
        Attribute attribute = attributes.get(type);
        if (attribute != null) {
            record = attribute.get().toString();
        }
        return record;
    }

    private static String extractPublicKey(String record) throws Exception {
        String[] tokens = record.split(";");
        String publicKey = null;
        for (String token : tokens) {
            if (token.trim().startsWith("p=")) {
                publicKey = token.trim().substring(2);
                break;
            }
        }
        return publicKey;
    }

    private static boolean verifyDKIM(String signature, String publicKey, MimeMessage message) throws Exception {
        message.saveChanges();
        byte[] bytes = getBytes(message);
        PublicKey key = getPublicKey(publicKey);
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(key);
        sig.update(bytes);
        return sig.verify(Base64.decodeBase64(signature.getBytes()));
    }

    private static PublicKey getPublicKey(String publicKey) throws Exception {
        byte[] decodedKey = Base64.decodeBase64(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static byte[] getBytes(MimeMessage message) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        message.writeTo(outputStream);
        return outputStream.toByteArray();
    }
}


