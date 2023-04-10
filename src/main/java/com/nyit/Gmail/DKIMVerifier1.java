package com.nyit.Gmail;

import java.io.IOException;
import java.util.List;

import org.xbill.DNS.*;
import org.apache.james.jdkim.*;
import org.apache.james.jdkim.exceptions.*;

public class DKIMVerifier1 {

    public static void main(String[] args) {

        // The DKIM domain and selector to lookup
        String domain = "gmail.com";
        String selector = "20210112";

        // The message to verify
        String message = "Message to verify";

        // The DKIM public key to verify against
        String publicKey = null;

        try {
            // Lookup the DKIM TXT record for the domain and selector
            Name name = Name.fromString(selector + "._domainkey." + domain, Name.root);
            Record[] records = new Lookup(name, Type.TXT).run();

            // Parse the DKIM public key from the TXT record
            for (Record record : records) {
                if (record instanceof TXTRecord) {
                    TXTRecord txtRecord = (TXTRecord) record;
                    List<String> strings = txtRecord.getStrings();
                    for (String string : strings) {
                        if (string.startsWith("p=")) {
                            publicKey = string.substring(2);
                            break;
                        }
                    }
                }
            }
        } catch (TextParseException e) {
            // Handle exception
            e.printStackTrace();
        } catch (IOException e) {
            // Handle exception
            e.printStackTrace();
        }

        if (publicKey == null) {
            // The DKIM public key could not be found
            System.out.println("DKIM public key not found");
            return;
        }

    }

}
