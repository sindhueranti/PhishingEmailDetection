package com.nyit.Gmail;

import org.xbill.DNS.*;

public class SPFValidator {
  public static boolean validateSPF(String domain) {
    try {
    	
    	domain = "gmail.com";
      // Lookup the SPF record for the domain
      Record[] records = new Lookup(domain, Type.TXT).run();
      
      // Iterate through the TXT records and check for an SPF record
      for (Record record : records) {
        if (record.getType() == Type.TXT) {
          TXTRecord txtRecord = (TXTRecord) record;
          String spfRecord = txtRecord.getStrings().get(0);
          
          // Check if the SPF record starts with "v=spf1"
          if (spfRecord.startsWith("v=spf1")) {
            // If the SPF record is valid, return true
            return true;
          }
        }
      }
    } catch (TextParseException e) {
      // Handle DNS lookup errors
      e.printStackTrace();
    }
    
    // If no valid SPF record was found, return false
    return false;
  }
}

