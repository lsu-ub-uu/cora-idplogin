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

import java.io.IOException;
import java.io.PrintWriter;

import org.owasp.encoder.Encode;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.uu.ub.cora.gatekeepertokenprovider.AuthToken;
import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProvider;
import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;
import se.uu.ub.cora.idplogin.json.IdpLoginOnlySharingKnownInformationException;
import se.uu.ub.cora.login.json.AuthTokenToJsonConverter;
import se.uu.ub.cora.login.json.AuthTokenToJsonConverterProvider;

public class IdpLoginServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String userIdFromIdp = request.getHeader("eppn");
		// the following two lines are left for now if we need the info when creating logins for
		// users that are not stored in the system prior to logging in
		// String lastName = request.getHeader("sn");
		// String firstName = request.getHeader("givenName");
		UserInfo userInfo = UserInfo.withLoginId(userIdFromIdp);
		AuthToken authTokenFromGatekeeper = getNewAuthTokenFromGatekeeper(userInfo);

		String url = IdpLoginInstanceProvider.getInitInfo().get("tokenLogoutURL");

		tryToCreateAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrlAndUserId(response,
				authTokenFromGatekeeper, url, userIdFromIdp);
	}

	private void tryToCreateAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrlAndUserId(
			HttpServletResponse response, AuthToken authTokenFromGatekeeper, String url,
			String userIdFromIdp) {
		try (PrintWriter out = response.getWriter();) {
			createAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrl(authTokenFromGatekeeper, url,
					out);
		} catch (IOException _) {
			throw IdpLoginOnlySharingKnownInformationException.forUserId(userIdFromIdp);
		}
	}

	private void createAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrl(AuthToken authToken,
			String url, PrintWriter out) {

		String mainSystemDomainEscaped = Encode
				.forJavaScript(IdpLoginInstanceProvider.getInitInfo().get("mainSystemDomain"));
		String tokenForHtml = Encode.forHtml(authToken.token());
		AuthTokenToJsonConverter converter = AuthTokenToJsonConverterProvider.getConverter();
		String jsonAuthToken = converter.convertAuthTokenToJson(authToken, url);
		String jsonAuthTokenEscaped = Encode.forJavaScript(jsonAuthToken);
		String outBlock = """
				<!DOCTYPE html>
				<html>
					<head>
						<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
						<script type="text/javascript">
							window.onload = start;
							function start() {
								var authentication = %s;
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
				""".formatted(jsonAuthTokenEscaped, mainSystemDomainEscaped, tokenForHtml);
		out.print(outBlock);
	}

	private AuthToken getNewAuthTokenFromGatekeeper(UserInfo userInfo) {
		GatekeeperTokenProvider gatekeeperTokenProvider = IdpLoginInstanceProvider
				.getGatekeeperTokenProvider();

		return gatekeeperTokenProvider.getAuthTokenForUserInfo(userInfo);
	}

}
