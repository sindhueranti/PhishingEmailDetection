package com.nyit.Gmail;

import org.apache.commons.lang3.StringUtils;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class DmarcValidator {
	public static String validateDmarc(String address, String authResults) {

		String[] addressParts = address.split("<");

		String emailId = addressParts[1].substring(0, addressParts[1].length() - 1);
		String domain = emailId.split("@")[1];
		String dmarcResponse = EmailConstants.FALSE;

		try {
			// Query the DMARC record using XBill DNS library
			Record[] records = new Lookup("_dmarc." + domain, Type.TXT).run();
			String authHeaders[] = authResults.split("; ");
			String dmarcValue = "";
			String dmarcRecord = "";

			for (String header : authHeaders) {
				if (header.contains("dmarc")) {
					dmarcValue = header.split("=")[1];
				}
			}

			// Check if there are any DMARC records for the domain
			if (records == null || records.length == 0) {
				System.out.println("Dmarc record not found for " + domain);
				dmarcResponse = EmailConstants.NOT_FOUND;
				return dmarcResponse;
			}

			for (Record record : records) {
				if (record instanceof TXTRecord) {
					TXTRecord txtRecord = (TXTRecord) record;
					String txtString = txtRecord.toString();
					if (txtString.contains("v=DMARC1")) {
						dmarcRecord = txtString.substring(txtString.indexOf("v=DMARC1"));
						dmarcResponse = EmailConstants.TRUE;
						break;
					} else {
						dmarcResponse = EmailConstants.FALSE;
					}
				}
			}

			// Check if the DMARC record exists and print it out
			if (dmarcRecord.isEmpty()) {
				System.out.println("DMARC record not found for " + domain);
				dmarcResponse = EmailConstants.NOT_FOUND;
			} else {
				System.out.println("DMARC record for " + domain + ": " + dmarcRecord);
			}

		} catch (TextParseException e) {
			System.out.println("Error checking DMARC record for " + domain + ": " + e.getMessage());
		}
		return dmarcResponse;
	}
}
