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
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import se.uu.ub.cora.idplogin.log.LoggerFactorySpy;
import se.uu.ub.cora.logger.LoggerProvider;

public class IdpLoginInitializerTest {
	private IdpLoginInitializer idpLoginInitializer;
	private ServletContext source;
	private ServletContextEvent context;
	private LoggerFactorySpy loggerFactorySpy;
	private String testedClassName = "IdpLoginInitializer";

	@BeforeMethod
	public void setUp() {
		loggerFactorySpy = new LoggerFactorySpy();
		LoggerProvider.setLoggerFactory(loggerFactorySpy);
		idpLoginInitializer = new IdpLoginInitializer();
		source = new ServletContextSpy();
		context = new ServletContextEvent(source);

	}

	@Test
	public void testGatekeeperTokenProviderIsSet() {
		setNeededInitParameters();
		assertNotNull(IdpLoginInstanceProvider.getGatekeeperTokenProvider());
	}

	private void setNeededInitParameters() {
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		source.setInitParameter("mainSystemDomain", "http://localhost:8080");
		source.setInitParameter("tokenLogoutURL",
				"http://localhost:8080/apptokenverifier/rest/apptoken/");
		idpLoginInitializer.contextInitialized(context);
	}

	@Test(expectedExceptions = RuntimeException.class, expectedExceptionsMessageRegExp = "Error "
			+ "starting IdpLogin: InitInfo must contain gatekeeperURL")
	public void testInitializeSystemWithoutGatekeeperURL() {
		source.setInitParameter("tokenLogoutURL",
				"http://localhost:8080/apptokenverifier/rest/apptoken/");
		source.setInitParameter("mainSystemDomain", "http://localhost:8080");

		idpLoginInitializer.contextInitialized(context);
	}

	@Test
	public void testErrorIsLoggedIfMissingGatekeeperURL() throws Exception {
		source.setInitParameter("tokenLogoutURL",
				"http://localhost:8080/apptokenverifier/rest/apptoken/");
		source.setInitParameter("mainSystemDomain", "http://localhost:8080");
		try {
			idpLoginInitializer.contextInitialized(context);
		} catch (Exception e) {

		}
		assertEquals(loggerFactorySpy.getFatalLogMessageUsingClassNameAndNo(testedClassName, 0),
				"InitInfo must contain gatekeeperURL");
	}

	@Test
	public void testInitInfoSetInIdpLoginInstanceProvider() throws Exception {
		setNeededInitParameters();
		assertEquals(IdpLoginInstanceProvider.getInitInfo().get("mainSystemDomain"),
				"http://localhost:8080");
	}

	@Test(expectedExceptions = RuntimeException.class, expectedExceptionsMessageRegExp = "Error "
			+ "starting IdpLogin: InitInfo must contain mainSystemDomain")
	public void testInitializeSystemWithoutMainSystemDomain() {
		source.setInitParameter("tokenLogoutURL",
				"http://localhost:8080/apptokenverifier/rest/apptoken/");
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		idpLoginInitializer.contextInitialized(context);
	}

	@Test
	public void testInitializeSystemWithoutMainSystemDomainSendsAlongInitalException() {
		source.setInitParameter("tokenLogoutURL",
				"http://localhost:8080/apptokenverifier/rest/apptoken/");
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		try {

			idpLoginInitializer.contextInitialized(context);
		} catch (Exception e) {
			assertTrue(e.getCause() instanceof RuntimeException);
		}
	}

	@Test
	public void testErrorIsLoggedIfMissingMainSystemDomain() throws Exception {
		source.setInitParameter("tokenLogoutURL",
				"http://localhost:8080/apptokenverifier/rest/apptoken/");
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		try {
			idpLoginInitializer.contextInitialized(context);
		} catch (Exception e) {

		}
		assertEquals(loggerFactorySpy.getFatalLogMessageUsingClassNameAndNo(testedClassName, 0),
				"InitInfo must contain mainSystemDomain");
	}

	@Test(expectedExceptions = RuntimeException.class, expectedExceptionsMessageRegExp = "Error "
			+ "starting IdpLogin: InitInfo must contain tokenLogoutURL")
	public void testInitializeSystemWithoutTokenLogoutURL() {
		source.setInitParameter("mainSystemDomain", "http://localhost:8080");
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		idpLoginInitializer.contextInitialized(context);
	}

	@Test
	public void testErrorIsLoggedIfMissingTokenLogoutURL() throws Exception {
		source.setInitParameter("mainSystemDomain", "http://localhost:8080");
		source.setInitParameter("gatekeeperURL", "http://localhost:8080/gatekeeper/");
		try {
			idpLoginInitializer.contextInitialized(context);
		} catch (Exception e) {

		}
		assertEquals(loggerFactorySpy.getFatalLogMessageUsingClassNameAndNo(testedClassName, 0),
				"InitInfo must contain tokenLogoutURL");
	}

	@Test
	public void testDestroySystem() {
		IdpLoginInitializer ApptokenInitializer = new IdpLoginInitializer();
		ApptokenInitializer.contextDestroyed(null);
		// TODO: should we do something on destroy?
	}

	@Test
	public void testLogMessagesOnStartUp() throws Exception {
		setNeededInitParameters();
		assertEquals(loggerFactorySpy.getInfoLogMessageUsingClassNameAndNo(testedClassName, 0),
				"IdpLoginInitializer starting...");
		assertEquals(loggerFactorySpy.getInfoLogMessageUsingClassNameAndNo(testedClassName, 1),
				"Found http://localhost:8080 as mainSystemDomain");
		assertEquals(loggerFactorySpy.getInfoLogMessageUsingClassNameAndNo(testedClassName, 2),
				"Found http://localhost:8080/apptokenverifier/rest/apptoken/ as tokenLogoutURL");
		assertEquals(loggerFactorySpy.getInfoLogMessageUsingClassNameAndNo(testedClassName, 3),
				"Found http://localhost:8080/gatekeeper/ as gatekeeperURL");
		assertEquals(loggerFactorySpy.getInfoLogMessageUsingClassNameAndNo(testedClassName, 4),
				"IdpLoginInitializer started");
	}
}
