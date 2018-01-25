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

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import se.uu.ub.cora.gatekeepertokenprovider.GatekeeperTokenProviderImp;
import se.uu.ub.cora.httphandler.HttpHandlerFactory;
import se.uu.ub.cora.httphandler.HttpHandlerFactoryImp;

@WebListener
public class IdpLoginInitializer implements ServletContextListener {
	private ServletContext servletContext;
	private HashMap<String, String> initInfo;

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		servletContext = arg0.getServletContext();
		try {
			tryToInitialize();
		} catch (Exception e) {
			throw new RuntimeException("Error starting IdpLogin: " + e.getMessage());
		}
	}

	private void tryToInitialize() {
		collectInitInformation();
		ensureidpLoginPublicPathToSystemExistsInInitInfo();
		IdpLoginInstanceProvider.setInitInfo(initInfo);
		createAndSetGatekeeperTokenProvider();
	}

	private void collectInitInformation() {
		initInfo = new HashMap<>();
		Enumeration<String> initParameterNames = servletContext.getInitParameterNames();
		while (initParameterNames.hasMoreElements()) {
			String key = initParameterNames.nextElement();
			initInfo.put(key, servletContext.getInitParameter(key));
		}
	}

	private void ensureidpLoginPublicPathToSystemExistsInInitInfo() {
		if (!initInfo.containsKey("idpLoginPublicPathToSystem")) {
			throw new RuntimeException("Context must have a idpLoginPublicPathToSystem set.");
		}
	}

	private void createAndSetGatekeeperTokenProvider() {
		String gatekeeperUrl = getInitParameter("gatekeeperURL");
		HttpHandlerFactory httpHandlerFactory = new HttpHandlerFactoryImp();
		IdpLoginInstanceProvider.setGatekeeperTokenProvider(GatekeeperTokenProviderImp
				.usingBaseUrlAndHttpHandlerFactory(gatekeeperUrl, httpHandlerFactory));
	}

	private String getInitParameter(String parameterName) {
		if (initInfo.containsKey(parameterName)) {
			return initInfo.get(parameterName);
		}
		throw new RuntimeException("Context must have a " + parameterName + " set.");
	}

	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		// not sure we need anything here
	}
}
