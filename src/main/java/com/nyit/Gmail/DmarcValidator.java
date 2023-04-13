package com.nyit.Gmail;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class DmarcValidator {
	public static String validateDmarc(String address) {
		
		String[] addressParts = address.split(" ");
		
		String emailId = addressParts[1].substring(1, addressParts[1].length()-1);
		String domain = emailId.split("@")[1];
		try {
			// Query the DMARC record using XBill DNS library
			Record[] records = new Lookup("_dmarc." + domain, Type.TXT).run();

			// Check if there are any DMARC records for the domain
			if (records == null || records.length == 0) {
				System.out.println("DMARC record not found for " + domain);
				return EmailConstants.NOT_FOUND;
			}

			// Extract the DMARC record from the TXT record
			String dmarcRecord = "";
			for (Record record : records) {
				if (record instanceof TXTRecord) {
					TXTRecord txtRecord = (TXTRecord) record;
					String txtString = txtRecord.toString();
					if (txtString.contains("v=DMARC1")) {
						dmarcRecord = txtString.substring(txtString.indexOf("v=DMARC1"));
						break;
					} else {
						return EmailConstants.FALSE;
					}
				}
			}

			// Check if the DMARC record exists and print it out
			if (dmarcRecord.isEmpty()) {
				System.out.println("DMARC record not found for " + domain);
				return EmailConstants.NOT_FOUND;
			} else {
				System.out.println("DMARC record for " + domain + ": " + dmarcRecord);
			}
		} catch (TextParseException e) {
			System.out.println("Error checking DMARC record for " + domain + ": " + e.getMessage());
		}
		return EmailConstants.TRUE;
	}
}