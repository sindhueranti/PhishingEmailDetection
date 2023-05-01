package com.nyit.Gmail;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class DKIMVerifier {

	public static String validateDKIM(String dkimheader) {

		String[] dkimParts = dkimheader.split("; ");

		// The DKIM domain and selector to lookup
		String domain = "";
		String selector = "";

		for (String part : dkimParts) {
			if (part.trim().startsWith("d=")) {
				domain = part.split("=")[1];
			} else if (part.trim().startsWith("s=")) {
				selector = part.split("=")[1];
			}
		}

		// The DKIM public key to verify against
		String publicKey = null;

		try {
			// Lookup the DKIM TXT record for the domain and selector
			Name name = Name.fromString(selector + "._domainkey." + domain);
			Record[] records = new Lookup(name, Type.TXT).run();

			if (null != records) {
				// Parse the DKIM public key from the TXT record
				for (Record record : records) {
					if (record instanceof TXTRecord) {
						String txtRecord = ((TXTRecord) records[0]).getStrings().get(0);
						if (txtRecord.trim().startsWith("v=DKIM1")) {
							String[] parts = txtRecord.split("; ");
							for (String part : parts) {
								if (part.trim().startsWith("p=")) {
									if (part.split("=").length == 2)
										publicKey = part.split("=")[1];
									break;
								}
							}
						} else {
							return EmailConstants.FALSE;
						}
					}
				}
			} else {
				return EmailConstants.NOT_FOUND;
			}
		} catch (TextParseException e) {
			System.out.println("Exception Occured when fetching DNS Records:" + e.getMessage());
			e.printStackTrace();
		}

		if (publicKey == null) {
			// The DKIM public key could not be found
			System.out.println("DKIM public key not found");
			return EmailConstants.NOT_FOUND;
		} else {
			return EmailConstants.TRUE;
		}

	}

}
