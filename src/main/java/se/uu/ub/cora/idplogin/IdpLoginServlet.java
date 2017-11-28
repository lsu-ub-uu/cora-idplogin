package se.uu.ub.cora.idplogin;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
		String authToken = authTokenFromGatekeeper.token;
		int validForNoSeconds = authTokenFromGatekeeper.validForNoSeconds;
		String idInUserStorage = authTokenFromGatekeeper.idInUserStorage;
		createAnswerHtmlToResponseUsingAuthToken(response, authToken, validForNoSeconds,
				idInUserStorage);
	}

	private void createAnswerHtmlToResponseUsingAuthToken(HttpServletResponse response,
			String authToken, int validForNoSeconds, String idInUserStorage) throws IOException {
		PrintWriter out = response.getWriter();
		out.println("<!DOCTYPE html>");
		out.println("<html><head>");
		out.println("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");

		out.println("<script type=\"text/javascript\">");
		out.println("window.onload = start;");
		out.println("function start() {");
		out.println("var authInfo = {");
		out.println("\"userId\" : \"Webredirect fake login\",");
		out.println("\"token\" : \"" + authToken + "\",");
		out.println("\"validForNoSeconds\" : \"" + validForNoSeconds + "\",");
		out.println("\"actionLinks\" : {");
		out.println("\"delete\" : {");
		out.println("\"requestMethod\" : \"DELETE\",");
		out.println("\"rel\" : \"delete\",");
		out.println("\"url\" : \"http://localhost:8080/apptokenverifier/rest/apptoken/"
				+ idInUserStorage + "\"");
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
		// } finally {
		out.close(); // Always close the output writer
		// }
	}

	private AuthToken getNewAuthTokenFromGatekeeper(UserInfo userInfo) {
		GatekeeperTokenProvider gatekeeperTokenProvider = IdpLoginInstanceProvider
				.getGatekeeperTokenProvider();

		return gatekeeperTokenProvider.getAuthTokenForUserInfo(userInfo);
	}

}
