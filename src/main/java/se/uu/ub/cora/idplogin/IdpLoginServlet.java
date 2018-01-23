package se.uu.ub.cora.idplogin;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.encoder.Encode;

import se.uu.ub.cora.gatekeepertokenprovider.AuthToken;
import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProvider;
import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;

public class IdpLoginServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String userIdFromIdp = request.getHeader("eppn");
		UserInfo userInfo = UserInfo.withLoginId(userIdFromIdp);
		AuthToken authTokenFromGatekeeper = getNewAuthTokenFromGatekeeper(userInfo);

		String url = getBaseURLWithCorrectProtocolFromRequest(request);

		createAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrl(response, authTokenFromGatekeeper,
				url);
	}

	private String getBaseURLWithCorrectProtocolFromRequest(HttpServletRequest request) {
		String baseURL = getBaseURLFromRequest(request);

		baseURL = changeHttpToHttpsIfHeaderSaysSo(request, baseURL);

		return baseURL;
	}

	private String getBaseURLFromRequest(HttpServletRequest request) {
		String tempUrl = request.getRequestURL().toString();
		String pathInfo = request.getServletPath();
		String baseURL = tempUrl.substring(0, tempUrl.lastIndexOf(pathInfo));
		baseURL += "/rest/logout/";
		return baseURL;
	}

	private String changeHttpToHttpsIfHeaderSaysSo(HttpServletRequest request, String baseURI) {
		String forwardedProtocol = request.getHeader("X-Forwarded-Proto");

		if (ifForwardedProtocolExists(forwardedProtocol)) {
			return baseURI.replaceAll("http:", forwardedProtocol + ":");
		}
		return baseURI;
	}

	private boolean ifForwardedProtocolExists(String forwardedProtocol) {
		return null != forwardedProtocol && !"".equals(forwardedProtocol);
	}

	private void createAnswerHtmlToResponseUsingResponseAndAuthTokenAndUrl(
			HttpServletResponse response, AuthToken authToken, String url) throws IOException {
		PrintWriter out = response.getWriter();
		out.println("<!DOCTYPE html>");
		out.println("<html><head>");
		out.println("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");

		out.println("<script type=\"text/javascript\">");
		out.println("window.onload = start;");
		out.println("function start() {");
		out.println("var authInfo = {");
		out.println("\"userId\" : \"Webredirect fake login\",");
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
		out.print("\"url\" : \"" + Encode.forJavaScript(url));
		out.print(Encode.forJavaScript(authToken.idInUserStorage));
		out.println("\"");
		out.println("}");
		out.println("}");
		out.println("};");
		out.println("window.opener.postMessage(authInfo, window.windowOpenedFromUrl);");

		out.println("window.opener.focus();");
		out.println("window.close();");
		out.println("}");
		out.println("</script>");

		out.println("<body>");
		out.println("</body></html>");
		out.close();
	}

	private AuthToken getNewAuthTokenFromGatekeeper(UserInfo userInfo) {
		GatekeeperTokenProvider gatekeeperTokenProvider = IdpLoginInstanceProvider
				.getGatekeeperTokenProvider();

		return gatekeeperTokenProvider.getAuthTokenForUserInfo(userInfo);
	}

}
