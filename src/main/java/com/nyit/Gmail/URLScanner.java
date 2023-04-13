/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.nyit.Gmail;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import me.vighnesh.api.virustotal.VirusTotalAPI;
import me.vighnesh.api.virustotal.dao.URLScanMetaData;

/**
 *
 * @author BVR vigneshb1210@gmail.com
 */
public class URLScanner {

    public static URLScanMetaData scanURL(URL url) throws IOException {
        VirusTotalAPI virusTotal = VirusTotalAPI.configure("API Key");
        URLScanMetaData scanURL = virusTotal.scanURL(url);
        System.out.println("---SCAN META DATA---");
        System.out.println("");
        System.out.println("URL : " + scanURL.getUrl());
        System.out.println("Resource : " + scanURL.getResource());
        System.out.println("Scan Date : " + scanURL.getScanDate());
        System.out.println("Scan Id : " + scanURL.getScanId());
        System.out.println("Response Code : " + scanURL.getResponseCode());
        System.out.println("Permalink : " + scanURL.getPermalink());
        System.out.println("VerboseMessage : " + scanURL.getVerboseMsg());
        return scanURL;
    }
    
    public static void main(String args[]) throws MalformedURLException {
    	URL url = new URL("https://links.email.nbc.com/u/click?_t=fa015b3b9bec40428d8906a7fd9b2677&_m=4e56985eb7a5422c81a315351e17cf54&_e=Y9jDu0GYsJWz1PIKvtivBS4JrBoAZAD2t7J1KGnNLQZSZVG2bSZo2kWwS40rgd8GH0gYhjf6mNnnn41RflyQQKjvIMO72MUFoeaAmfP8RCsdLTYNQxWLrHGPr3VGklV2x6Srhk_AyfAOZj36Cz74OjpnH8IlQpGeDNVZ3i5TLIS0QQNjl3LKtw4uV6Kz4MymUi0TU6AQ12sqNOMv1zeb752ba0_vvix91BYT0djbWL0%3D");
    	try {
			scanURL(url);
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
}
