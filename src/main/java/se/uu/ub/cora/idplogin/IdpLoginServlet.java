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
		UserInfo userInfo = UserInfo.withIdInUserStorage("141414");
		AuthToken authTokenFromGatekeeper = getNewAuthTokenFromGatekeeper(userInfo);
		String authToken = authTokenFromGatekeeper.token;
		int validForNoSeconds = authTokenFromGatekeeper.validForNoSeconds;
		String idInUserStorage = authTokenFromGatekeeper.idInUserStorage;

		String url = getBaseURLWithCorrectProtocolFromRequest(request);

		createAnswerHtmlToResponseUsingAuthToken(response, authToken, validForNoSeconds,
				idInUserStorage, url);
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

	private void createAnswerHtmlToResponseUsingAuthToken(HttpServletResponse response,
			String authToken, int validForNoSeconds, String idInUserStorage, String url)
			throws IOException {
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
		out.print(Encode.forJavaScript(authToken));
		out.println("\",");
		out.print("\"validForNoSeconds\" : \"");
		out.print(validForNoSeconds);
		out.println("\",");
		out.println("\"actionLinks\" : {");
		out.println("\"delete\" : {");
		out.println("\"requestMethod\" : \"DELETE\",");
		out.println("\"rel\" : \"delete\",");
		out.print("\"url\" : \"" + Encode.forJavaScript(url));
		out.print(Encode.forJavaScript(idInUserStorage));
		out.println("\"");
		out.println("}");
		out.println("}");
		out.println("};");
		out.println("window.opener.jsClient.getDependencies().globalInstances.loginManager");
		out.println(".appTokenAuthInfoCallback(authInfo);");
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
