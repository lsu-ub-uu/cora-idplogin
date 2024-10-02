/*
 * Copyright 2017, 2018, 2021 Uppsala University Library
 *
 * This file is part of Cora.
 *
 *     Cora is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     Cora is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with Cora.  If not, see <http://www.gnu.org/licenses/>.
 */

package se.uu.ub.cora.idplogin;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import org.owasp.encoder.Encode;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServlet;
import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;
import se.uu.ub.cora.idplogin.json.IdpLoginOnlySharingKnownInformationException;

public class IdpLoginServletTest {

	private GatekeeperTokenProviderSpy gatekeeperTokenProvider;
	private IdpLoginServlet loginServlet;
	private RequestSpy requestSpy;
	private ResponseSpy responseSpy;
	private String authToken;
	private String validForNoSeconds;
	// private String idInUserStorage;
	private Map<String, String> initInfo = new HashMap<>();

	@BeforeMethod
	public void setup() {
		gatekeeperTokenProvider = new GatekeeperTokenProviderSpy();
		initInfo.put("mainSystemDomain", "http://localhost:8080");
		initInfo.put("tokenLogoutURL", "http://localhost:8080/login/rest/apptoken/");
		IdpLoginInstanceProvider.setInitInfo(initInfo);
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);
		loginServlet = new IdpLoginServlet();
		requestSpy = new RequestSpy();
		responseSpy = new ResponseSpy();

		authToken = "someAuth'Token";
		validForNoSeconds = "278";
		// idInUserStorage = "someIdInUser\\x27Storage";

	}

	@Test
	public void testInit() {
		assertTrue(loginServlet instanceof HttpServlet);
	}

	@Test
	public void testDoGetEppnSentOnToGateKeeper() throws Exception {
		requestSpy.headers.put("eppn", "test@testing.org");

		loginServlet.doGet(requestSpy, responseSpy);

		UserInfo userInfo = gatekeeperTokenProvider.userInfos.get(0);
		assertEquals(userInfo.loginId, "test@testing.org");
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswerOverHttps() throws Exception {
		requestSpy.headers.put("X-Forwarded-Proto", "https");
		requestSpy.headers.put("eppn", "test@testing.org");
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtml(authToken, validForNoSeconds);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswerOverHttpForEmptyHeader() throws Exception {
		requestSpy.headers.put("X-Forwarded-Proto", "");
		requestSpy.headers.put("eppn", "test@testing.org");
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtml(authToken, validForNoSeconds);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswerOverHttpForMissingHeader() throws Exception {
		requestSpy.headers.put("eppn", "test@testing.org");
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtml(authToken, validForNoSeconds);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswer() throws Exception {
		requestSpy.headers.put("eppn", "test@testing.org");
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtml(authToken, validForNoSeconds);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	private String createExpectedHtml(String authToken, String validForNoSeconds) {

		StringJoiner html = new StringJoiner("\n");
		html.add("<!DOCTYPE html>");
		html.add("<html><head>");
		html.add("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
		html.add("<script type=\"text/javascript\">");
		html.add("window.onload = start;");
		html.add("function start() {");
		html.add("var authInfo = {");
		html.add("\"userId\" : \"loginId\",");
		html.add("\"token\" : \"" + Encode.forJavaScript(authToken) + "\",");
		html.add("\"loginId\" : \"loginId\",");
		html.add("\"validForNoSeconds\" : \"" + validForNoSeconds + "\",");
		html.add("\"actionLinks\" : {");
		html.add("\"delete\" : {");
		html.add("\"requestMethod\" : \"DELETE\",");
		html.add("\"rel\" : \"delete\",");
		html.add("\"url\" : \"http:\\/\\/localhost:8080\\/login\\/rest\\/apptoken\\/loginId\"");
		html.add("}");
		html.add("}");
		html.add("};");
		html.add("if(null!=window.opener){");
		html.add("window.opener.postMessage(authInfo, \"http:\\/\\/localhost:8080\");");
		html.add("window.opener.focus();");
		html.add("window.close();");
		html.add("}");
		html.add("}");
		html.add("</script>");
		html.add("<body>");
		html.add("token: " + Encode.forHtml(authToken));
		html.add("</body></html>");
		html.add("");
		return html.toString();
	}

	@Test(expectedExceptions = IdpLoginOnlySharingKnownInformationException.class, expectedExceptionsMessageRegExp = ""
			+ "test@testing.org")
	public void testGetWhenError() throws Exception {
		requestSpy.headers.put("eppn", "test@testing.org");
		responseSpy.throwIOExceptionOnGetWriter = true;
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtml(authToken, validForNoSeconds);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}
}
