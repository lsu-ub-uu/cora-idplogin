/*
 * Copyright 2017, 2018, 2021, 2025 Uppsala University Library
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServlet;
import se.uu.ub.cora.gatekeepertokenprovider.AuthToken;
import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;
import se.uu.ub.cora.gatekeepertokenprovider.json.AuthTokenToJsonConverterProvider;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;
import se.uu.ub.cora.idplogin.json.IdpLoginOnlySharingKnownInformationException;

public class IdpLoginServletTest {
	private static final String MAIN_SYSTEM_DOMAIN = "http://localhost:8080";
	private static final String TOKEN_LOGOUT_URL = "http://localhost:8080/login/rest/authToken/";
	private static final String ACCEPT = "application/vnd.cora.authentication+json";
	private GatekeeperTokenProviderSpy gatekeeperTokenProvider;
	private IdpLoginServlet loginServlet;
	private RequestSpy requestSpy;
	private ResponseSpy responseSpy;
	private Map<String, String> initInfo = new HashMap<>();
	private AuthTokenToJsonConverterSpy tokenConverterSpy;
	private AuthToken authToken;
	private Set<String> permissionUnits;

	@BeforeMethod
	public void setup() {
		setupGatekeeperTokenProviderSpy();
		setupAuthTokenConverterSpy();

		initInfo.put("mainSystemDomain", MAIN_SYSTEM_DOMAIN);
		initInfo.put("tokenLogoutURL", TOKEN_LOGOUT_URL);
		IdpLoginInstanceProvider.setInitInfo(initInfo);
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);
		loginServlet = new IdpLoginServlet();
		requestSpy = new RequestSpy();
		responseSpy = new ResponseSpy();
		requestSpy.headers.put("eppn", "test@testing.org");
		requestSpy.headers.put("sn", "some'LastName");
		requestSpy.headers.put("givenName", "some'FirstName");
	}

	private void setupGatekeeperTokenProviderSpy() {
		gatekeeperTokenProvider = new GatekeeperTokenProviderSpy();
		permissionUnits = new LinkedHashSet<>();
		permissionUnits.add("001");
		permissionUnits.add("002");
		authToken = new AuthToken("someAuth'Token", "someTokenId", 100L, 200L,
				"someIdInUser'Storage", "loginId", Optional.empty(), Optional.empty(),
				permissionUnits);
		gatekeeperTokenProvider.MRV.setDefaultReturnValuesSupplier("getAuthTokenForUserInfo",
				() -> authToken);
	}

	private void setupAuthTokenConverterSpy() {
		tokenConverterSpy = new AuthTokenToJsonConverterSpy();
		AuthTokenToJsonConverterProvider.onlyForTestSetConverterSupplier(() -> tokenConverterSpy);
	}

	@AfterMethod
	public void afterMethod() {
		AuthTokenToJsonConverterProvider.resetSupplier();
	}

	@Test
	public void testIsServlet() {
		assertTrue(loginServlet instanceof HttpServlet);
	}

	@Test
	public void testDoGetEppnSentOnToGateKeeper() throws Exception {
		loginServlet.doGet(requestSpy, responseSpy);

		UserInfo userInfo = (UserInfo) gatekeeperTokenProvider.MCR
				.getParameterForMethodAndCallNumberAndParameter("getAuthTokenForUserInfo", 0,
						"userInfo");
		assertEquals(userInfo.loginId, "test@testing.org");
	}

	@Test
	public void testDoGetEppnSentOnToGateKeeperForAccept() throws Exception {
		requestSpy.headers.put("accept", ACCEPT);

		loginServlet.doGet(requestSpy, responseSpy);

		UserInfo userInfo = (UserInfo) gatekeeperTokenProvider.MCR
				.getParameterForMethodAndCallNumberAndParameter("getAuthTokenForUserInfo", 0,
						"userInfo");
		assertEquals(userInfo.loginId, "test@testing.org");
		String convertedToken = (String) tokenConverterSpy.MCR.assertCalledParametersReturn(
				"convertAuthTokenToJson", authToken, TOKEN_LOGOUT_URL);

		assertEquals(new String(responseSpy.stream.toByteArray()), convertedToken);
		assertEquals(responseSpy.headers.get("Content-Type"), ACCEPT);
	}

	@DataProvider(name = "protocolType")
	public Iterator<String> testCasesForProtcols() {
		return Arrays.asList("https", "http", "").iterator();
	}

	@Test(dataProvider = "protocolType")
	public void testGetCreatesCorrectHtmlAnswerOverParameterizedProtocolTypeHeader(String protocol)
			throws Exception {
		requestSpy.headers.put("accept", "notOurAccept");
		requestSpy.headers.put("X-Forwarded-Proto", protocol);
		loginServlet.doGet(requestSpy, responseSpy);

		assertCorrectHtmlWithAuthenticationInResponseFromSpy();

		tokenConverterSpy.MCR.assertCalledParameters("convertAuthTokenToJson", authToken,
				TOKEN_LOGOUT_URL);
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswerOverHttpForMissingHeaderWithPermissionUnits()
			throws Exception {
		loginServlet.doGet(requestSpy, responseSpy);

		assertCorrectHtmlWithAuthenticationInResponseFromSpy();
	}

	@Test(expectedExceptions = IdpLoginOnlySharingKnownInformationException.class, expectedExceptionsMessageRegExp = ""
			+ "test@testing.org")
	public void testGetWhenError() throws Exception {
		responseSpy.throwIOExceptionOnGetWriter = true;
		loginServlet.doGet(requestSpy, responseSpy);

		assertCorrectHtmlWithAuthenticationInResponseFromSpy();

	}

	private void assertCorrectHtmlWithAuthenticationInResponseFromSpy() {
		String mainSystemDomainEscaped = "http:\\/\\/localhost:8080";
		String tokenForHtml = "someAuth&#39;Token";
		String expectedHtml = """
				<!DOCTYPE html>
				<html>
					<head>
						<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
						<script type="text/javascript">
							window.onload = start;
							function start() {
								var authentication = fake json \\x27authtoken\\x27 from AuthTokenToJsonConverterSpy;
								if(null!=window.opener){
									window.opener.postMessage(authentication, "%s");
									window.opener.focus();
									window.close();
								}
							};
						</script>
					</head>
					<body>
						token: %s
					</body>
				</html>
				"""
				.formatted(mainSystemDomainEscaped, tokenForHtml);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}
}
