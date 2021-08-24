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

import java.util.Enumeration;
import java.util.HashMap;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProviderImp;
import se.uu.ub.cora.httphandler.HttpHandlerFactory;
import se.uu.ub.cora.httphandler.HttpHandlerFactoryImp;
import se.uu.ub.cora.logger.Logger;
import se.uu.ub.cora.logger.LoggerProvider;

@WebListener
public class IdpLoginInitializer implements ServletContextListener {
	private ServletContext servletContext;
	private HashMap<String, String> initInfo;
	private Logger log = LoggerProvider.getLoggerForClass(IdpLoginInitializer.class);

	@Override
	public void contextInitialized(ServletContextEvent contextEvent) {
		servletContext = contextEvent.getServletContext();
		try {
			tryToInitialize();
		} catch (Exception e) {
			throw new RuntimeException("Error starting IdpLogin: " + e.getMessage(), e);
		}
	}

	private void tryToInitialize() {
		String simpleName = IdpLoginInitializer.class.getSimpleName();
		log.logInfoUsingMessage(simpleName + " starting...");
		collectInitInformation();
		ensureParametersExistInInitInfo();
		IdpLoginInstanceProvider.setInitInfo(initInfo);
		createAndSetGatekeeperTokenProvider();
		log.logInfoUsingMessage(simpleName + " started");

	}

	private void collectInitInformation() {
		initInfo = new HashMap<>();
		Enumeration<String> initParameterNames = servletContext.getInitParameterNames();
		while (initParameterNames.hasMoreElements()) {
			String key = initParameterNames.nextElement();
			initInfo.put(key, servletContext.getInitParameter(key));
		}
	}

	private void ensureParametersExistInInitInfo() {
		tryToGetInitParameter("mainSystemDomain");
		tryToGetInitParameter("tokenLogoutURL");
		tryToGetInitParameter("gatekeeperURL");
	}

	private String tryToGetInitParameter(String parameterName) {
		throwErrorIfKeyIsMissingFromInitInfo(parameterName);
		String parameter = initInfo.get(parameterName);
		log.logInfoUsingMessage("Found " + parameter + " as " + parameterName);
		return parameter;
	}

	private void throwErrorIfKeyIsMissingFromInitInfo(String parameterName) {
		if (!initInfo.containsKey(parameterName)) {
			String errorMessage = "InitInfo must contain " + parameterName;
			log.logFatalUsingMessage(errorMessage);
			throw new RuntimeException(errorMessage);
		}
	}

	private void createAndSetGatekeeperTokenProvider() {
		String gatekeeperUrl = initInfo.get("gatekeeperURL");
		HttpHandlerFactory httpHandlerFactory = new HttpHandlerFactoryImp();
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(GatekeeperTokenProviderImp
				.usingBaseUrlAndHttpHandlerFactory(gatekeeperUrl, httpHandlerFactory));
	}

	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		// not sure we need anything here
	}
}
