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

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import se.uu.ub.cora.idplogin.initialize.IdpLoginInstanceProvider;

public class IdpLoginEndpointTest {
	private Response response;

	@BeforeMethod
	public void setup() {
		GatekeeperTokenProviderSpy gatekeeperTokenProvider = new GatekeeperTokenProviderSpy();
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);
	}

	private void assertResponseStatusIs(Status responseStatus) {
		assertEquals(response.getStatusInfo(), responseStatus);
	}

	@Test
	public void testRemoveAuthTokenForUser() {
		UriInfo uriInfo = new TestUri();
		IdpLoginEndpoint appTokenEndpoint = new IdpLoginEndpoint(uriInfo);

		String userId = "someUserId";
		String authToken = "someAuthToken";

		response = appTokenEndpoint.removeAuthTokenForAppToken(userId, authToken);
		assertResponseStatusIs(Response.Status.OK);
	}

	@Test
	public void testRemoveAuthTokenForUserWrongToken() {
		GatekeeperTokenProviderErrorSpy gatekeeperTokenProvider = new GatekeeperTokenProviderErrorSpy();
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);

		UriInfo uriInfo = new TestUri();
		IdpLoginEndpoint appTokenEndpoint = new IdpLoginEndpoint(uriInfo);

		String userId = "someUserId";
		String authToken = "someAuthTokenNotFound";

		response = appTokenEndpoint.removeAuthTokenForAppToken(userId, authToken);
		assertResponseStatusIs(Response.Status.NOT_FOUND);
	}

}
