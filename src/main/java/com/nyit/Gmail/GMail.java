package com.nyit.Gmail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePartHeader;
import com.google.api.services.gmail.model.Thread;

import io.restassured.path.json.JsonPath;
import me.vighnesh.api.virustotal.dao.URLScanMetaData;
import me.vighnesh.api.virustotal.dao.URLScanReport;

/**
 * Date: May 31st, 2020
 * 
 * @author NaveenKhunteta
 *
 */
public class GMail {
	private static final String APPLICATION_NAME = "PhishingEmailDetection";
	private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	private static final String USER_ID = "me";
	/**
	 * Global instance of the scopes required by this quickstart. If modifying these
	 * scopes, delete your previously saved tokens/ folder.
	 */
	private static final List<String> SCOPES = Collections.singletonList(GmailScopes.MAIL_GOOGLE_COM);
	private static final String CREDENTIALS_FILE_PATH = System.getProperty("user.dir") + File.separator + "src"
			+ File.separator + "main" + File.separator + "resources" + File.separator + "credentials" + File.separator
			+ "credentials_new.json";

	private static final String TOKENS_DIRECTORY_PATH = System.getProperty("user.dir") + File.separator + "src"
			+ File.separator + "main" + File.separator + "resources" + File.separator + "credentials";

	/**
	 * Creates an authorized Credential object.
	 * 
	 * @param HTTP_TRANSPORT The network HTTP Transport.
	 * @return An authorized Credential object.
	 * @throws IOException If the credentials.json file cannot be found.
	 */
	private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
		// Load client secrets.
		InputStream in = new FileInputStream(new File(CREDENTIALS_FILE_PATH));
		if (in == null) {
			throw new FileNotFoundException("Resource not found: " + CREDENTIALS_FILE_PATH);
		}
		GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));
		// Build flow and trigger user authorization request.
		GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY,
				clientSecrets, SCOPES)
				.setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
				.setAccessType("offline").build();
		LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(9999).build();
		return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
	}

	public static Gmail getService() throws IOException, GeneralSecurityException {
		// Build a new authorized API client service.
		final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
		Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
				.setApplicationName(APPLICATION_NAME).build();
		return service;
	}

	public static List<Message> listMessagesMatchingQuery(Gmail service, String userId, String query)
			throws IOException {
		ListMessagesResponse response = service.users().messages().list(userId).setQ(query).execute();
		List<Message> messages = new ArrayList<Message>();
		while (response.getMessages() != null) {
			messages.addAll(response.getMessages());
			if (response.getNextPageToken() != null) {
				String pageToken = response.getNextPageToken();
				response = service.users().messages().list(userId).setQ(query).setPageToken(pageToken).execute();
			} else {
				break;
			}
		}
		return messages;
	}

	public static Message getMessage(Gmail service, String userId, List<Message> messages, int index)
			throws IOException {
		Message message = service.users().messages().get(userId, messages.get(index).getId()).execute();
		return message;
	}

	public static Message getRawMessage(Gmail service, String userId, List<Message> messages, int index)
			throws IOException {
		Message message = service.users().messages().get(userId, messages.get(index).getId()).setFormat("raw")
				.execute();
		return message;
	}

	public static HashMap<String, String> getGmailData(String query) {
		try {
			Gmail service = getService();
			List<Message> messages = new ArrayList<Message>();
			messages = listMessagesMatchingQuery(service, USER_ID, query);
			Message message = getMessage(service, USER_ID, messages, 0);
			JsonPath jp = new JsonPath(message.toString());
			System.out.println("Message is:" + message.toString());
			List<MessagePartHeader> headers = message.getPayload().getHeaders();
			String dkimValue = "";
			String spfValue = "";
			Integer positives = 0;
			Integer total = 0;
			int positivePer = 0;
			String isDkimValid = EmailConstants.FALSE;
			String dmarcValue = "";

			String subject = jp.getString("payload.headers.find { it.name == 'Subject' }.value");
			String sentTo = jp.getString("payload.headers.find { it.name == 'To' }.value");
			String sentFrom = jp.getString("payload.headers.find { it.name == 'From' }.value");
			String body = "";
			if (null != jp.getString("payload.parts[0]"))
				body = new String(Base64.getDecoder().decode(jp.getString("payload.parts[0].body.data")));
			else
				body = message.getSnippet();

			for (MessagePartHeader header : headers) {
				if ("DKIM-Signature".equals(header.getName())) {
					dkimValue = header.getValue();
				} else if ("Received-SPF".equals(header.getName())) {
					spfValue = header.getValue();
				}
			}
			System.out.println("DKIM Value is:" + dkimValue);
			if (!StringUtils.isEmpty(dkimValue)) {
				isDkimValid = DKIMVerifier.validateDKIM(dkimValue);
				System.out.println("DKIM Is valid:" + isDkimValid);
			}

			String isDmarcValid = DmarcValidator.validateDmarc(sentFrom, dmarcValue);
			System.out.println("Dmarc Is valid:" + isDmarcValid);

			String isSpfValid = SPFValidator.validateSPF(sentFrom, spfValue);
			System.out.println("SPF is Valid:" + isSpfValid);

			String link = null;
			String arr[] = body.split("\n");
			for (String s : arr) {
				s = s.trim();
				if (s.startsWith("http") || s.startsWith("https")) {
					link = s.trim();
				}
			}

			System.out.println("Link is: " + link);

			if (!StringUtils.isEmpty(link)) {

				URL url = new java.net.URL(link);
				URLScanReport urlReport = GetUrlReport.getURLReport(url);

				if (0 == urlReport.getResponseCode()) {
					System.out.println(
							"Theres is no Report available for the url Provied. Calling the Scan URL Service.");
					URLScanMetaData scanURL = URLScanner.scanURL(url);
					if (null != scanURL && 0 == scanURL.getResponseCode()) {
						System.out.println("Fetching the report from GetUrlReport class.");
						urlReport = GetUrlReport.getURLReport(url);
						if (0 != urlReport.getResponseCode()) {
							positives = urlReport.getPositives();
							total = urlReport.getTotal();
							positivePer = (int) Math.round(EmailValidator.calculatePercentage(positives, total));
						}
					}
				} else {
					positives = urlReport.getPositives();
					total = urlReport.getTotal();
					positivePer = (int) Math.round(EmailValidator.calculatePercentage(positives, total));
				}
			}

			boolean isValidEmail = EmailValidator.isValidEmail(isSpfValid, isDmarcValid, isDkimValid, positives, total);
			System.out.println(isValidEmail);

			HashMap<String, String> hm = new HashMap<String, String>();
			System.out.println("Sent To:" + sentTo);
			System.out.println("Sent From:" + sentFrom);
			hm.put("to", sentTo);
			hm.put("from", sentFrom);
			hm.put("subject", subject);
			hm.put("body", body);
			hm.put("link", link);
			return hm;
		} catch (Exception e) {
			System.out.println("email not found....");
			throw new RuntimeException(e);
		}
	}

	public static EmailResponse validateEmail(String emailId) {

		EmailResponse emailResponse = new EmailResponse();

		try {
			Gmail service = getService();
			List<Message> messages = new ArrayList<Message>();
			String query = "label:unread";
			Integer positives = 0;
			Integer total = 0;
			int positivePer = 0;
			String isDkimValid = EmailConstants.FALSE;
			messages = listMessagesMatchingQuery(service, USER_ID, query);
			Message message = getMessage(service, USER_ID, messages, 0);
			JsonPath jp = new JsonPath(message.toString());
			System.out.println("Message is:" + message.toString());
			List<MessagePartHeader> headers = message.getPayload().getHeaders();
			String dkimValue = "";
			String spfValue = "";
			String authHeaders = "";
			List<String> linkList = new ArrayList();

			String sentFrom = jp.getString("payload.headers.find { it.name == 'From' }.value");
			String body = "";
			String bodyStr = "";
			if (null != jp.getString("payload.parts[0]")) {
				bodyStr = jp.getString("payload.parts[0].body.data");
				body = new String(Base64.getUrlDecoder().decode(bodyStr));
			} else
				body = message.getSnippet();
			for (MessagePartHeader header : headers) {
				if ("DKIM-Signature".equals(header.getName())) {
					dkimValue = header.getValue();
				} else if ("Received-SPF".equals(header.getName())) {
					spfValue = header.getValue();
				} else if ("Authentication-Results".equals(header.getName())) {
					authHeaders = header.getValue();
				}
			}

			System.out.println("Authentication Header:" + authHeaders);
			System.out.println("DKIM Value is:" + dkimValue);
			if (!StringUtils.isEmpty(dkimValue)) {
				isDkimValid = DKIMVerifier.validateDKIM(dkimValue);
			}
			System.out.println("DKIM Is valid:" + isDkimValid);

			String isDmarcValid = DmarcValidator.validateDmarc(sentFrom, authHeaders);
			System.out.println("Dmarc Is valid:" + isDmarcValid);

			String isSpfValid = SPFValidator.validateSPF(sentFrom, spfValue);
			System.out.println("SPF is Valid:" + isSpfValid);

			String link = null;
			if (body.startsWith("<html>")) {
				Document doc = Jsoup.parse(body);
				Elements links = doc.select("a[href]");
				for (Element linkn : links)
					linkList.add(linkn.attr("abs:href"));
			}
			if (linkList.size() > 0) {
				link = linkList.get(0);
			}
			if (StringUtils.isEmpty(link)) {
				String arr[] = body.split("\n");
				if (arr.length == 1)
					arr = body.split("<br/>");
				for (String s : arr) {
					s = s.trim();
					if (s.startsWith("http") || s.startsWith("https")) {
						link = s.trim();
					}
				}
			}

			System.out.println("Link is: " + link);

			if (!StringUtils.isEmpty(link)) {

				URL url = new java.net.URL(link);
				URLScanReport urlReport = GetUrlReport.getURLReport(url);

				if (0 == urlReport.getResponseCode()) {
					System.out.println(
							"Theres is no Report available for the url Provied. Calling the Scan URL Service.");
					URLScanMetaData scanURL = URLScanner.scanURL(url);
					if (null != scanURL && 0 == scanURL.getResponseCode()) {
						System.out.println("Fetching the report from GetUrlReport class.");
						urlReport = GetUrlReport.getURLReport(url);
						if (0 != urlReport.getResponseCode()) {
							positives = urlReport.getPositives();
							total = urlReport.getTotal();
							positivePer = (int) Math.round(EmailValidator.calculatePercentage(positives, total));
						}
					}
				} else {
					positives = urlReport.getPositives();
					total = urlReport.getTotal();
					positivePer = (int) Math.round(EmailValidator.calculatePercentage(positives, total));
				}
			}

			boolean isValidEmail = EmailValidator.isValidEmail(isSpfValid, isDmarcValid, isDkimValid, positives, total);

			emailResponse.setIsValidDKIM(isDkimValid);
			emailResponse.setIsValidDmarc(isDmarcValid);
			emailResponse.setIsValidSPF(isSpfValid);
			emailResponse.setPositivePer(positivePer);
			if (isValidEmail)
				emailResponse.setEmailValidationResult(EmailConstants.VALID_EMAIL);
			else
				emailResponse.setEmailValidationResult(EmailConstants.INVALID_EMAIL);

			EmailResponseDAO.insertEmailResponseData(emailResponse);

			System.out.println("Response Inserted Successfully");

		} catch (Exception e) {
			System.out.println("Exception Occured while trying to Validate the Email");
			if (e instanceof IndexOutOfBoundsException)
				throw new IndexOutOfBoundsException();
			else if (e instanceof SQLException) {
				System.out.println("Exception occured when trying to insert the Record:" + e.getMessage());
			} else
				throw new RuntimeException(e);
		}
		return emailResponse;
	}

	public static int getTotalCountOfMails() {
		int size;
		try {
			final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
			Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
					.setApplicationName(APPLICATION_NAME).build();
			List<Thread> threads = service.users().threads().list("me").execute().getThreads();
			size = threads.size();
		} catch (Exception e) {
			System.out.println("Exception log " + e);
			size = -1;
		}
		return size;
	}

	public static boolean isMailExist(String messageTitle) {
		try {
			final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
			Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
					.setApplicationName(APPLICATION_NAME).build();
			ListMessagesResponse response = service.users().messages().list("me").setQ("subject:" + messageTitle)
					.execute();
			List<Message> messages = getMessages(response);
			return messages.size() != 0;
		} catch (Exception e) {
			System.out.println("Exception log" + e);
			return false;
		}
	}

	private static List<Message> getMessages(ListMessagesResponse response) {
		List<Message> messages = new ArrayList<Message>();
		try {
			final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
			Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
					.setApplicationName(APPLICATION_NAME).build();
			while (response.getMessages() != null) {
				messages.addAll(response.getMessages());
				if (response.getNextPageToken() != null) {
					String pageToken = response.getNextPageToken();
					response = service.users().messages().list(USER_ID).setPageToken(pageToken).execute();
				} else {
					break;
				}
			}
			return messages;
		} catch (Exception e) {
			System.out.println("Exception log " + e);
			return messages;
		}
	}

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		HashMap<String, String> hm = getGmailData("label:unread");
		System.out.println(hm.get("subject"));
		System.out.println("=================");
		System.out.println(hm.get("body"));
		System.out.println("=================");
		System.out.println(hm.get("link"));

		System.out.println("=================");
		System.out.println("Total count of emails is :" + getTotalCountOfMails());

		System.out.println("=================");
		boolean exist = isMailExist("new link");
		System.out.println("title exist or not: " + exist);

	}
}