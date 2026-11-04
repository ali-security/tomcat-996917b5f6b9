/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.websocket;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.websocket.ClientEndpointConfig;
import javax.websocket.ContainerProvider;
import javax.websocket.DeploymentException;
import javax.websocket.HandshakeResponse;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.WebSocketContainer;
import javax.websocket.server.HandshakeRequest;
import javax.websocket.server.ServerContainer;
import javax.websocket.server.ServerEndpoint;
import javax.websocket.server.ServerEndpointConfig;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.servlets.DefaultServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.websocket.TesterMessageCountClient.BasicText;
import org.apache.tomcat.websocket.TesterMessageCountClient.TesterProgrammaticEndpoint;
import org.apache.tomcat.websocket.server.WsContextListener;

/**
 * Any {@code Authorization} header the client has been configured with (or that the client generated in response to a
 * 401 challenge) is scoped to the host that issued the challenge. Once the HTTP exchange that used it has completed it
 * must be discarded so that it is never presented to a different host - e.g. the target of a redirect.
 */
public class TestWsWebSocketContainerAuthorization extends WebSocketBaseTest {

    private static final String HOST_NAME = "localhost";

    private static final String PATH_TARGET = "/target";
    private static final String PATH_REDIRECT = "/redirect";

    private static final String MESSAGE_STRING = "authorization-test-message";

    // Base64 of "tomcat:tomcat-pass"
    private static final String AUTHORIZATION_HEADER_VALUE = "Basic dG9tY2F0OnRvbWNhdC1wYXNz";


    @Before
    public void resetRecordedHeaders() {
        TesterConfigurator.reset();
        RedirectServlet.reset();
    }


    /**
     * The credentials must not be left in the user properties once the HTTP exchange that used them has completed. If
     * they are, the same {@code ClientEndpointConfig} instance will present them to the next - possibly unrelated - host
     * it is used to connect to.
     */
    @Test
    public void testAuthorizationHeaderRemovedAfterUpgrade() throws Exception {
        startAuthorizationTestServer();

        ClientEndpointConfig clientEndpointConfig = ClientEndpointConfig.Builder.create().build();
        clientEndpointConfig.getUserProperties().put(Constants.AUTHORIZATION_HEADER_NAME,
                AUTHORIZATION_HEADER_VALUE);

        WebSocketContainer wsContainer = ContainerProvider.getWebSocketContainer();
        try {
            Session wsSession = wsContainer.connectToServer(TesterProgrammaticEndpoint.class, clientEndpointConfig,
                    new URI("ws://" + HOST_NAME + ":" + getPort() + PATH_TARGET));

            // Confirm the test is exercising the code under test - the
            // credentials were presented to the host that was connected to.
            Assert.assertTrue(TesterConfigurator.isHandshakeSeen());
            Assert.assertEquals(AUTHORIZATION_HEADER_VALUE, TesterConfigurator.getAuthorizationHeader());

            // Confirm the connection is usable
            CountDownLatch latch = new CountDownLatch(1);
            BasicText handler = new BasicText(latch);
            wsSession.addMessageHandler(handler);
            wsSession.getBasicRemote().sendText(MESSAGE_STRING);
            Assert.assertTrue(handler.getLatch().await(10, TimeUnit.SECONDS));
            Queue<String> messages = handler.getMessages();
            Assert.assertEquals(1, messages.size());
            Assert.assertEquals(MESSAGE_STRING, messages.peek());

            // The fix. The credentials must have been discarded.
            Assert.assertNull(clientEndpointConfig.getUserProperties().get(Constants.AUTHORIZATION_HEADER_NAME));
        } finally {
            ((WsWebSocketContainer) wsContainer).destroy();
        }
    }


    /**
     * The credentials for the original host must not be presented to the target of a redirect.
     */
    @Test
    public void testAuthorizationHeaderNotSentToRedirectTarget() throws Exception {
        startAuthorizationTestServer();

        ClientEndpointConfig clientEndpointConfig = ClientEndpointConfig.Builder.create().build();
        clientEndpointConfig.getUserProperties().put(Constants.AUTHORIZATION_HEADER_NAME,
                AUTHORIZATION_HEADER_VALUE);

        WebSocketContainer wsContainer = ContainerProvider.getWebSocketContainer();
        try {
            Session wsSession = wsContainer.connectToServer(TesterProgrammaticEndpoint.class, clientEndpointConfig,
                    new URI("ws://" + HOST_NAME + ":" + getPort() + PATH_REDIRECT));

            // Confirm the test is exercising the code under test - the
            // credentials were presented to the original host and the redirect
            // was followed to the WebSocket end point.
            Assert.assertEquals(AUTHORIZATION_HEADER_VALUE, RedirectServlet.getAuthorizationHeader());
            Assert.assertTrue(TesterConfigurator.isHandshakeSeen());

            // Confirm the connection is usable
            CountDownLatch latch = new CountDownLatch(1);
            BasicText handler = new BasicText(latch);
            wsSession.addMessageHandler(handler);
            wsSession.getBasicRemote().sendText(MESSAGE_STRING);
            Assert.assertTrue(handler.getLatch().await(10, TimeUnit.SECONDS));
            Queue<String> messages = handler.getMessages();
            Assert.assertEquals(1, messages.size());
            Assert.assertEquals(MESSAGE_STRING, messages.peek());

            // The fix. The credentials must not have been presented to the
            // target of the redirect.
            Assert.assertNull(TesterConfigurator.getAuthorizationHeader());
            Assert.assertNull(clientEndpointConfig.getUserProperties().get(Constants.AUTHORIZATION_HEADER_NAME));
        } finally {
            ((WsWebSocketContainer) wsContainer).destroy();
        }
    }


    private void startAuthorizationTestServer() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        // No file system docBase required
        Context ctx = tomcat.addContext("", null);
        ctx.addApplicationListener(Config.class.getName());
        Tomcat.addServlet(ctx, "default", new DefaultServlet());
        ctx.addServletMappingDecoded("/", "default");
        Tomcat.addServlet(ctx, "redirect", new RedirectServlet());
        ctx.addServletMappingDecoded(PATH_REDIRECT, "redirect");

        tomcat.start();
    }


    public static class Config extends WsContextListener {

        @Override
        public void contextInitialized(ServletContextEvent sce) {
            super.contextInitialized(sce);
            ServerContainer sc = (ServerContainer) sce.getServletContext().getAttribute(
                    org.apache.tomcat.websocket.server.Constants.SERVER_CONTAINER_SERVLET_CONTEXT_ATTRIBUTE);
            try {
                sc.addEndpoint(Target.class);
            } catch (DeploymentException e) {
                throw new IllegalStateException(e);
            }
        }
    }


    @ServerEndpoint(value = PATH_TARGET, configurator = TesterConfigurator.class)
    public static class Target {

        @OnMessage
        public void echoTextMessage(Session session, String msg) {
            try {
                session.getBasicRemote().sendText(msg);
            } catch (IOException e) {
                try {
                    session.close();
                } catch (IOException ioe) {
                    // Ignore
                }
            }
        }
    }


    /**
     * Records the {@code Authorization} header (if any) presented with the WebSocket handshake request.
     */
    public static class TesterConfigurator extends ServerEndpointConfig.Configurator {

        private static volatile boolean handshakeSeen = false;
        private static volatile String authorizationHeader = null;

        public static void reset() {
            handshakeSeen = false;
            authorizationHeader = null;
        }

        public static boolean isHandshakeSeen() {
            return handshakeSeen;
        }

        public static String getAuthorizationHeader() {
            return authorizationHeader;
        }

        @Override
        public void modifyHandshake(ServerEndpointConfig sec, HandshakeRequest request, HandshakeResponse response) {
            List<String> values = request.getHeaders().get(Constants.AUTHORIZATION_HEADER_NAME);
            if (values != null && !values.isEmpty()) {
                authorizationHeader = values.get(0);
            }
            handshakeSeen = true;
            super.modifyHandshake(sec, request, response);
        }
    }


    /**
     * Redirects the WebSocket handshake request to {@link #PATH_TARGET} and records the {@code Authorization} header (if
     * any) presented with the original request.
     */
    public static class RedirectServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static volatile String authorizationHeader = null;

        public static void reset() {
            authorizationHeader = null;
        }

        public static String getAuthorizationHeader() {
            return authorizationHeader;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            authorizationHeader = req.getHeader(Constants.AUTHORIZATION_HEADER_NAME);
            resp.setStatus(HttpServletResponse.SC_FOUND);
            resp.setHeader(Constants.LOCATION_HEADER_NAME, PATH_TARGET);
        }
    }
}
