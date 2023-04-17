package com.nyit.Gmail;

import org.apache.commons.lang3.StringUtils;
import org.xbill.DNS.*;

public class SPFValidator {
	public static String validateSPF(String address, String spfValue) {
		try {

			String[] addressParts = address.split("<");

			String emailId = addressParts[1].substring(0, addressParts[1].length() - 1);
			String domain = emailId.split("@")[1];

			// Lookup the SPF record for the domain
			Record[] records = new Lookup(domain, Type.TXT).run();

			if (records == null || records.length == 0) {
				System.out.println("SPF record not found for " + domain);
				if (StringUtils.isEmpty(spfValue))
					return EmailConstants.NOT_FOUND;
				else if (spfValue.contains("pass"))
					return EmailConstants.TRUE;
				else
					return EmailConstants.FALSE;
			}

			// Iterate through the TXT records and check for an SPF record
			for (Record record : records) {
				if (record.getType() == Type.TXT) {
					TXTRecord txtRecord = (TXTRecord) record;
					String spfRecord = txtRecord.getStrings().get(0);

					// Check if the SPF record starts with "v=spf1"
					if (spfRecord.startsWith("v=spf1")) {
						// If the SPF record is valid, return true
						return EmailConstants.TRUE;
					} else {
						return EmailConstants.FALSE;
					}
				}
			}
		} catch (TextParseException e) {
			// Handle DNS lookup errors
			e.printStackTrace();
		}

		// If no valid SPF record was found, return false
		return EmailConstants.FALSE;
	}
}
