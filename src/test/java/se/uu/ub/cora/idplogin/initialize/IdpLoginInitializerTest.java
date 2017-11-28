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

package se.uu.ub.cora.idplogin.initialize;

import static org.testng.Assert.assertNotNull;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class IdpLoginInitializerTest {
	private IdpLoginInitializer idpLoginInitializer;
	private ServletContext source;
	private ServletContextEvent context;

	@BeforeMethod
	public void setUp() {
		idpLoginInitializer = new IdpLoginInitializer();
		source = new ServletContextSpy();
		context = new ServletContextEvent(source);

	}

	@Test
	public void testGatekeeperTokenProviderIsSet() {
		source.setInitParameter("appTokenStorageClassName",
				"se.uu.ub.cora.idplogin.AppTokenStorageSpy");
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		idpLoginInitializer.contextInitialized(context);
		assertNotNull(IdpLoginInstanceProvider.getGatekeeperTokenProvider());
	}

	@Test(expectedExceptions = RuntimeException.class)
	public void testInitializeSystemWithoutGatekeeperURL() {
		idpLoginInitializer.contextInitialized(context);
	}

	@Test
	public void testDestroySystem() {
		IdpLoginInitializer ApptokenInitializer = new IdpLoginInitializer();
		ApptokenInitializer.contextDestroyed(null);
		// TODO: should we do something on destroy?
	}
}
