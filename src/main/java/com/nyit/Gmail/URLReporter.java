/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.nyit.Gmail;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import me.vighnesh.api.virustotal.VirusTotalAPI;
import me.vighnesh.api.virustotal.dao.URLScan;
import me.vighnesh.api.virustotal.dao.URLScanReport;

public class URLReporter {

    public static void main(String[] args) throws MalformedURLException {
        URL url = new URL("https://storage.googleapis.com/t01trxin.html#4gekuoalv868mziwk27lzidyuyuhlqquh1479mhzjqnwpjl99297gugehed7dspbxspepgrgt11");
        VirusTotalAPI virusTotal = VirusTotalAPI.configure("d391871b14f3946f70de145e5ec32837d3cb0016f3048c21cb9c73b56d745e75");
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
        
        if(urlReport.getResponseCode()!=0) {

        Map<String, URLScan> scans = urlReport.getScans();
        System.out.println("---URL REPORT---");
        System.out.println("");
        scans.keySet().stream().forEach((String scan) -> {
            URLScan report = scans.get(scan);
            System.out.println(scan + "\t:" + report.getReport());
        });
        }
    }
}
