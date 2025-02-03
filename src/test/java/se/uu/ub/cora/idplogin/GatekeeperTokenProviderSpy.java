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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import se.uu.ub.cora.gatekeepertokenprovider.AuthToken;
import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProvider;
import se.uu.ub.cora.gatekeepertokenprovider.UserInfo;

public class GatekeeperTokenProviderSpy implements GatekeeperTokenProvider {

	public List<UserInfo> userInfos = new ArrayList<>();
	public List<String> deletedUserInfos = new ArrayList<>();

	@Override
	public AuthToken getAuthTokenForUserInfo(UserInfo userInfo) {
		userInfos.add(userInfo);
		return new AuthToken("someAuth'Token", "someTokenId", 100L, 200L, "someIdInUser'Storage",
				"loginId", Optional.empty(), Optional.empty());
	}

	@Override
	public void removeAuthToken(String tokenId, String authToken) {
		deletedUserInfos.add(tokenId);

	}

	@Override
	public AuthToken renewAuthToken(String tokenId, String token) {
		return null;
	}

}
