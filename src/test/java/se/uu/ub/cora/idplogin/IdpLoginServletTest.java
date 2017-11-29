/*
 * Copyright 2017 Uppsala University Library
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

import javax.servlet.http.HttpServlet;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;

public class IdpLoginServletTest {

	private GatekeeperTokenProviderSpy gatekeeperTokenProvider;
	private IdpLoginServlet loginServlet;
	private RequestSpy requestSpy;
	private ResponseSpy responseSpy;

	@BeforeMethod
	public void setup() {
		gatekeeperTokenProvider = new GatekeeperTokenProviderSpy();
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);
		loginServlet = new IdpLoginServlet();
		requestSpy = new RequestSpy();
		responseSpy = new ResponseSpy();
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
		// assertEquals(userInfo.idFromLogin, "test@testing.org");
		assertEquals(userInfo.idInUserStorage, "141414");
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswer() throws Exception {
		requestSpy.headers.put("eppn", "test@testing.org");
		loginServlet.doGet(requestSpy, responseSpy);

		String authToken = "someAuthToken";
		String validForNoSeconds = "278";
		String idInUserStorage = "someIdInUserStorage";

		String expectedHtml = createExpectedHtml(authToken, validForNoSeconds, idInUserStorage);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	private String createExpectedHtml(String authToken, String validForNoSeconds,
			String idInUserStorage) {
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>");
		sb.append("\n");
		sb.append("<html><head>");
		sb.append("\n");
		sb.append("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
		sb.append("\n");

		sb.append("<script type=\"text/javascript\">");
		sb.append("\n");
		sb.append("window.onload = start;");
		sb.append("\n");
		sb.append("function start() {");
		sb.append("\n");
		sb.append("var authInfo = {");
		sb.append("\n");
		sb.append("\"userId\" : \"Webredirect fake login\",");
		sb.append("\n");
		sb.append("\"token\" : \"" + authToken + "\",");
		sb.append("\n");
		sb.append("\"validForNoSeconds\" : \"" + validForNoSeconds + "\",");
		sb.append("\n");
		sb.append("\"actionLinks\" : {");
		sb.append("\n");
		sb.append("\"delete\" : {");
		sb.append("\n");
		sb.append("\"requestMethod\" : \"DELETE\",");
		sb.append("\n");
		sb.append("\"rel\" : \"delete\",");
		sb.append("\n");
		sb.append("\"url\" : \"http://localhost:8080/apptokenverifier/rest/apptoken/"
				+ idInUserStorage + "\"");
		sb.append("\n");
		sb.append("}");
		sb.append("\n");
		sb.append("}");
		sb.append("\n");
		sb.append("};");
		sb.append("\n");
		sb.append("window.opener.jsClient.getDependencies().globalInstances.loginManager");
		sb.append("\n");
		sb.append(".appTokenAuthInfoCallback(authInfo);");
		sb.append("\n");
		sb.append("window.opener.focus();");
		sb.append("\n");
		sb.append("window.close();");
		sb.append("\n");
		sb.append("}");
		sb.append("\n");
		sb.append("</script>");
		sb.append("\n");

		sb.append("<body>");
		sb.append("\n");
		sb.append("</body></html>");
		sb.append("\n");
		return sb.toString();
	}

}
