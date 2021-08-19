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

public class IdpLoginServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String userIdFromIdp = request.getHeader("eppn");
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
		} catch (IOException e) {
			throw IdpLoginOnlySharingKnownInformationException.forUserId(userIdFromIdp);
		}
	}

	private void createAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrl(AuthToken authToken,
			String url, PrintWriter out) {
		out.println("<!DOCTYPE html>");
		out.println("<html><head>");
		out.println("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");

		out.println("<script type=\"text/javascript\">");
		out.println("window.onload = start;");
		out.println("function start() {");
		out.println("var authInfo = {");
		out.println("\"userId\" : \"" + Encode.forJavaScript(authToken.idFromLogin) + "\",");
		out.print("\"token\" : \"");
		out.print(Encode.forJavaScript(authToken.token));
		out.println("\",");
		out.print("\"idFromLogin\" : \"");
		out.print(Encode.forJavaScript(authToken.idFromLogin));
		out.println("\",");
		out.print("\"validForNoSeconds\" : \"");
		out.print(authToken.validForNoSeconds);
		out.println("\",");
		out.println("\"actionLinks\" : {");
		out.println("\"delete\" : {");
		out.println("\"requestMethod\" : \"DELETE\",");
		out.println("\"rel\" : \"delete\",");
		out.print("\"url\" : \"" + Encode.forJavaScript(url + authToken.idInUserStorage));
		out.println("\"");
		out.println("}");
		out.println("}");
		out.println("};");
		out.println("if(null!=window.opener){");
		out.println(
				"window.opener.postMessage(authInfo, \""
						+ Encode.forJavaScript(
								IdpLoginInstanceProvider.getInitInfo().get("mainSystemDomain"))
						+ "\");");

		out.println("window.opener.focus();");
		out.println("window.close();");
		out.println("}");
		out.println("}");
		out.println("</script>");

		out.println("<body>");
		out.println("token: " + Encode.forHtml(authToken.token));
		out.println("</body></html>");
	}

	private AuthToken getNewAuthTokenFromGatekeeper(UserInfo userInfo) {
		GatekeeperTokenProvider gatekeeperTokenProvider = IdpLoginInstanceProvider
				.getGatekeeperTokenProvider();

		return gatekeeperTokenProvider.getAuthTokenForUserInfo(userInfo);
	}

}
