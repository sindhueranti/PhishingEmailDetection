package com.nyit.Gmail;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePart;
import com.google.api.services.gmail.model.MessagePartHeader;

import io.restassured.path.json.JsonPath;

public class DKIMPublicKeyExample {

  public static void main(String[] args) throws Exception {
  
    String selector = "20210112";
    String domain = "gmail.com";
  
    String recordName = selector + "._domainkey." + domain;
    Record[] records = new Lookup(recordName, Type.TXT).run();
    
    if (records == null) {
        throw new IOException("No DKIM record found for " + domain);
      }
      String txtRecord = ((TXTRecord) records[0]).getStrings().get(0);
      String[] parts = txtRecord.split("; ");
      String publicKeyString = "";
      for (String part : parts) {
          if(part.startsWith("p=")) {
        	  publicKeyString = part.split("=")[1];
          }
        };
        
      byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
      PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(publicKey);
      signature.update(message.getBytes());
      byte[] signatureBytes = Base64.getDecoder().decode(signatureValue);
      System.out.println(signature.verify(signatureBytes));

  
  }
  
  

}

