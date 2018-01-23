/*
 * Copyright 2017, 2018 Uppsala University Library
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

package se.uu.ub.cora.idplogin.initialize;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.Test;

import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProvider;
import se.uu.ub.cora.idplogin.GatekeeperTokenProviderSpy;

public class IdpLoginInstanceProviderTest {
	@Test
	public void testPrivateConstructor() throws Exception {
		Constructor<IdpLoginInstanceProvider> constructor = IdpLoginInstanceProvider.class
				.getDeclaredConstructor();
		assertTrue(Modifier.isPrivate(constructor.getModifiers()));
	}

	@Test(expectedExceptions = InvocationTargetException.class)
	public void testPrivateConstructorInvoke() throws Exception {
		Constructor<IdpLoginInstanceProvider> constructor = IdpLoginInstanceProvider.class
				.getDeclaredConstructor();
		assertTrue(Modifier.isPrivate(constructor.getModifiers()));
		constructor.setAccessible(true);
		constructor.newInstance();
	}

	@Test
	public void testGatekeeperTokenProvider() {
		GatekeeperTokenProvider gatekeeperTokenProvider = new GatekeeperTokenProviderSpy();
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(gatekeeperTokenProvider);
		assertEquals(IdpLoginInstanceProvider.getGatekeeperTokenProvider(),
				gatekeeperTokenProvider);
	}

	@Test
	public void testSetInitInfo() throws Exception {
		Map<String, String> initInfo = new HashMap<>();
		IdpLoginInstanceProvider.setInitInfo(initInfo);
		assertEquals(IdpLoginInstanceProvider.getInitInfo(), initInfo);
	}
}
