package com.nyit.Gmail;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import me.vighnesh.api.virustotal.VirusTotalAPI;
import me.vighnesh.api.virustotal.dao.URLScan;
import me.vighnesh.api.virustotal.dao.URLScanReport;

public class GetUrlReport {

	public static URLScanReport getURLReport(URL url) throws MalformedURLException {

		VirusTotalAPI virusTotal = VirusTotalAPI
				.configure("d391871b14f3946f70de145e5ec32837d3cb0016f3048c21cb9c73b56d745e75");
		URLScanReport urlReport = virusTotal.getURLReport(url);
		System.out.println("---SCAN META DATA---");
		System.out.println("");
		System.out.println("Response Code : " + urlReport.getResponseCode());
		System.out.println("Resource : " + urlReport.getResource());
		System.out.println("Scan ID : " + urlReport.getScanId());
		System.out.println("Permalink : " + urlReport.getPermalink());
		System.out.println("Scan Date : " + urlReport.getScanDate());
		System.out.println("Positives : " + urlReport.getPositives());
		System.out.println("Total : " + urlReport.getTotal());
		System.out.println("File Scan Id : " + urlReport.getFilescanId());

		if (urlReport.getResponseCode() != 0) {

			Map<String, URLScan> scans = urlReport.getScans();
			System.out.println("---URL REPORT---");
			System.out.println("");
			scans.keySet().stream().forEach((String scan) -> {
				URLScan report = scans.get(scan);
				System.out.println(scan + "\t:" + report.getReport());
			});
		}

		return urlReport;
	}
	
	public static void main (String args[]) throws MalformedURLException {
		
		URL url = new URL("https://links.email.nbc.com/u/click?_t=fa015b3b9bec40428d8906a7fd9b2677&_m=4e56985eb7a5422c81a315351e17cf54&_e=Y9jDu0GYsJWz1PIKvtivBS4JrBoAZAD2t7J1KGnNLQZSZVG2bSZo2kWwS40rgd8GH0gYhjf6mNnnn41RflyQQKjvIMO72MUFoeaAmfP8RCsdLTYNQxWLrHGPr3VGklV2x6Srhk_AyfAOZj36Cz74OjpnH8IlQpGeDNVZ3i5TLIS0QQNjl3LKtw4uV6Kz4MymUi0TU6AQ12sqNOMv1zeb752ba0_vvix91BYT0djbWL0%3D");
		getURLReport(url);
	}

}
