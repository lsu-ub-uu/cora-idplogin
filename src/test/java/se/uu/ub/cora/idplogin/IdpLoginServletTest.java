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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServlet;
import se.uu.ub.cora.gatekeepertokenprovider.AuthToken;
import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;
import se.uu.ub.cora.idplogin.json.IdpLoginOnlySharingKnownInformationException;

public class IdpLoginServletTest {

	private GatekeeperTokenProviderSpy gatekeeperTokenProvider;
	private IdpLoginServlet loginServlet;
	private RequestSpy requestSpy;
	private ResponseSpy responseSpy;
	private String validUntil;
	private String renewUntil;
	private Map<String, String> initInfo = new HashMap<>();

	@BeforeMethod
	public void setup() {
		gatekeeperTokenProvider = new GatekeeperTokenProviderSpy();
		initInfo.put("mainSystemDomain", "http://localhost:8080");
		initInfo.put("tokenLogoutURL", "http://localhost:8080/login/rest/authToken/");
		IdpLoginInstanceProvider.setInitInfo(initInfo);
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);
		loginServlet = new IdpLoginServlet();
		requestSpy = new RequestSpy();
		responseSpy = new ResponseSpy();
		requestSpy.headers.put("eppn", "test@testing.org");
		requestSpy.headers.put("sn", "some'LastName");
		requestSpy.headers.put("givenName", "some'FirstName");

		validUntil = "100";
		renewUntil = "200";
	}

	@Test
	public void testInit() {
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

	@DataProvider(name = "protocolType")
	public Iterator<String> testCasesForProtcols() {
		return Arrays.asList("https", "http", "").iterator();
	}

	@Test(dataProvider = "protocolType")
	public void testGetCreatesCorrectHtmlAnswerOverParameterizedProtocolTypeHeader(String protocol)
			throws Exception {
		requestSpy.headers.put("X-Forwarded-Proto", protocol);
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtmlWithoutPermissionUnits(validUntil, renewUntil);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswerOverHttpForMissingHeader() throws Exception {
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtmlWithoutPermissionUnits(validUntil, renewUntil);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	private String createExpectedHtmlWithoutPermissionUnits(String validUntil, String renewUntil) {
		String userIdEscaped = "someIdInUser\\x27Storage";
		String tokenEscaped = "someAuth\\x27Token";
		String lastNameEscaped = "some\\x27LastName";
		String firstNameEscaped = "some\\x27FirstName";
		String loginIdEscaped = "loginId";
		String actionUrlEscaped = "http:\\/\\/localhost:8080\\/login\\/rest\\/authToken\\/someTokenId";
		String mainSystemDomainEscaped = "http:\\/\\/localhost:8080";
		String tokenForHtml = "someAuth&#39;Token";

		return """
				<!DOCTYPE html>
				<html>
					<head>
						<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
						<script type="text/javascript">
							window.onload = start;
							function start() {
								var authentication = {
									"authentication" : {
										"data" : {
											"children" : [
												{"name" : "token", "value" : "%s"},
												{"name" : "validUntil", "value" : "%s"},
												{"name" : "renewUntil", "value" : "%s"},
												{"name" : "userId", "value" : "%s"},
												{"name" : "loginId", "value" : "%s"},
												{"name" : "firstName", "value" : "%s"},
												{"name" : "lastName", "value" : "%s"}
											],
											"name" : "authToken"
										},
										"actionLinks" : {
											"renew" : {
												"requestMethod" : "POST",
												"rel" : "renew",
												"url" : "%s",
												"accept": "application/vnd.cora.authentication+json"
											},
											"delete" : {
												"requestMethod" : "DELETE",
												"rel" : "delete",
												"url" : "%s"
											}
										}
									}
								};
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
				""".formatted(tokenEscaped, validUntil, renewUntil, userIdEscaped, loginIdEscaped,
				firstNameEscaped, lastNameEscaped, actionUrlEscaped, actionUrlEscaped,
				mainSystemDomainEscaped, tokenForHtml);
	}

	@Test
	public void testGetCreatesCorrectHtmlAnswerOverHttpForMissingHeaderWithPermissionUnits()
			throws Exception {
		Set<String> permissionUnits = new LinkedHashSet<>();
		permissionUnits.add("001");
		permissionUnits.add("002");

		gatekeeperTokenProvider.MRV.setDefaultReturnValuesSupplier("getAuthTokenForUserInfo",
				() -> new AuthToken("someAuth'Token", "someTokenId", 100L, 200L,
						"someIdInUser'Storage", "loginId", Optional.empty(), Optional.empty(),
						permissionUnits));
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtmlTwoPermissionUnits(validUntil, renewUntil);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}

	private String createExpectedHtmlTwoPermissionUnits(String validUntil, String renewUntil) {
		String userIdEscaped = "someIdInUser\\x27Storage";
		String tokenEscaped = "someAuth\\x27Token";
		String lastNameEscaped = "some\\x27LastName";
		String firstNameEscaped = "some\\x27FirstName";
		String loginIdEscaped = "loginId";
		String actionUrlEscaped = "http:\\/\\/localhost:8080\\/login\\/rest\\/authToken\\/someTokenId";
		String mainSystemDomainEscaped = "http:\\/\\/localhost:8080";
		String tokenForHtml = "someAuth&#39;Token";

		return """
				<!DOCTYPE html>
				<html>
					<head>
						<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
						<script type="text/javascript">
							window.onload = start;
							function start() {
								var authentication = {
									"authentication" : {
										"data" : {
											"children" : [
												{"name" : "token", "value" : "%s"},
												{"name" : "validUntil", "value" : "%s"},
												{"name" : "renewUntil", "value" : "%s"},
												{"name" : "userId", "value" : "%s"},
												{"name" : "loginId", "value" : "%s"},
												{"name" : "firstName", "value" : "%s"},
												{"name" : "lastName", "value" : "%s"},
												{
													"repeatId" : "1",
													"children" : [
														{"name" : "linkedRecordType", "value" : "permissionUnit"},
														{"name" : "linkedRecordId", "value" : "001"}
													],
													"name" : "permissionUnit"
												},
												{
													"repeatId" : "2",
													"children" : [
														{"name" : "linkedRecordType", "value" : "permissionUnit"},
														{"name" : "linkedRecordId", "value" : "002"}
													],
													"name" : "permissionUnit"
												}
											],
											"name" : "authToken"
										},
										"actionLinks" : {
											"renew" : {
												"requestMethod" : "POST",
												"rel" : "renew",
												"url" : "%s",
												"accept": "application/vnd.cora.authentication+json"
											},
											"delete" : {
												"requestMethod" : "DELETE",
												"rel" : "delete",
												"url" : "%s"
											}
										}
									}
								};
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
				.formatted(tokenEscaped, validUntil, renewUntil, userIdEscaped, loginIdEscaped,
						firstNameEscaped, lastNameEscaped, actionUrlEscaped, actionUrlEscaped,
						mainSystemDomainEscaped, tokenForHtml);
	}

	@Test(expectedExceptions = IdpLoginOnlySharingKnownInformationException.class, expectedExceptionsMessageRegExp = ""
			+ "test@testing.org")
	public void testGetWhenError() throws Exception {
		responseSpy.throwIOExceptionOnGetWriter = true;
		loginServlet.doGet(requestSpy, responseSpy);

		String expectedHtml = createExpectedHtmlWithoutPermissionUnits(validUntil, renewUntil);
		assertEquals(new String(responseSpy.stream.toByteArray()), expectedHtml);
	}
}
