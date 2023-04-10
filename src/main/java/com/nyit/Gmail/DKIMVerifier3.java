package com.nyit.Gmail;

import javax.mail.internet.MimeMessage;
import javax.mail.Session;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;
import javax.mail.Message;
import java.util.Properties;
import javax.mail.NoSuchProviderException;
import javax.mail.Transport;
import javax.mail.MessagingException;
import javax.mail.internet.AddressException;
import java.security.Security;
import javax.mail.internet.MimeMultipart;
import java.security.Key;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

public class DKIMVerifier3 {

    private String domain;
    private String selector;
    private PrivateKey privateKey;
    private String signature;

    public DKIMVerifier3(String domain, String selector, PrivateKey privateKey, String signature) {
        this.domain = domain;
        this.selector = selector;
        this.privateKey = privateKey;
        this.signature = signature;
    }

    public boolean verify(MimeMessage message) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        message.writeTo(outputStream);
        byte[] emailBytes = outputStream.toByteArray();
        String publicKey = "";

        // extract the DKIM-Signature header
        String dkimHeader = (String) message.getHeader("DKIM-Signature")[0];

        // extract the signature value from the header
        Pattern pattern = Pattern.compile("bh=[^;]+;\\s+b=([^\r\n]+)");
        Matcher matcher = pattern.matcher(dkimHeader);
        matcher.find();
        String signatureValue = matcher.group(1);

        // decode the signature value
        byte[] decodedSignatureValue = Base64.getDecoder().decode(signatureValue);

        // verify the signature
        Signature signature = Signature.getInstance("SHA256withRSA");
       // signature.initVerify((PublicKey) publicKey);
        signature.update(emailBytes);
        return signature.verify(decodedSignatureValue);
    }

    

}
