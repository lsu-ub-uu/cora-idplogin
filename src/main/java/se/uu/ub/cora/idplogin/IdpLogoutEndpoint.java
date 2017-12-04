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

import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProvider;
import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;

@Path("logout")
public class IdpLogoutEndpoint {

	private Response buildResponse(Status status) {
		return Response.status(status).build();
	}

	@DELETE
	@Path("{userid}")
	public Response removeAuthTokenForAppToken(@PathParam("userid") String userId,
			String authToken) {
		try {
			return tryToRemoveAuthTokenForUser(userId, authToken);
		} catch (Exception error) {
			return buildResponse(Response.Status.NOT_FOUND);
		}
	}

	private Response tryToRemoveAuthTokenForUser(String userId, String authToken) {
		GatekeeperTokenProvider gatekeeperTokenProvider = IdpLoginInstanceProvider
				.getGatekeeperTokenProvider();
		gatekeeperTokenProvider.removeAuthTokenForUser(userId, authToken);
		return buildResponse(Status.OK);
	}
}
