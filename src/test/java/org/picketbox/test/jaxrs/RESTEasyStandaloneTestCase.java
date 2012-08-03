/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketbox.test.jaxrs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.json.JSONObject;
import org.junit.Test;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.webapp.WebAppContext;
import org.picketbox.core.util.KeyStoreUtil;
import org.picketbox.jaxrs.filters.JWEInterceptor;
import org.picketbox.json.token.JSONWebToken;
import org.picketbox.test.http.jetty.EmbeddedWebServerBase;

/**
 * Unit test RESTEasy integration with PicketBox
 *
 * @author anil saldhana
 * @since Aug 2, 2012
 */
public class RESTEasyStandaloneTestCase extends EmbeddedWebServerBase {

    @Override
    protected void establishUserApps() {
        ClassLoader tcl = Thread.currentThread().getContextClassLoader();
        if (tcl == null) {
            tcl = getClass().getClassLoader();
        }

        final String WEBAPPDIR = "resteasy/standalone";

        final String CONTEXTPATH = "/*";

        // for localhost:port/admin/index.html and whatever else is in the webapp directory
        final URL warUrl = tcl.getResource(WEBAPPDIR);
        final String warUrlString = warUrl.toExternalForm();

        WebAppContext context = new WebAppContext(warUrlString, CONTEXTPATH);

        context.setContextPath("/");
        ServletHolder servletHolder = new ServletHolder(new HttpServletDispatcher());
        servletHolder.setInitParameter("javax.ws.rs.Application", TestApplicationConfig.class.getName());
        context.addServlet(servletHolder, "/*");

        // context.setParentLoaderPriority(true);
        server.setHandler(context);
    }

    /**
     * This testcase tests that a regular non-json payload is returned without any encryption
     *
     * @throws Exception
     */
    @Test
    public void testPlainText() throws Exception {

        String urlStr = "http://localhost:11080/rest/bookstore/books";
        URL url = new URL(urlStr);

        DefaultHttpClient httpclient = null;
        try {

            httpclient = new DefaultHttpClient();

            HttpGet httpget = new HttpGet(url.toExternalForm());

            httpget.setHeader(JWEInterceptor.CLIENT_ID, "1234");

            System.out.println("executing request:" + httpget.getRequestLine());
            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();

            System.out.println("----------------------------------------");
            StatusLine statusLine = response.getStatusLine();
            System.out.println(statusLine);
            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }

            InputStream is = entity.getContent();
            String contentString = getContentAsString(is);
            System.out.println("Plain Text=" + contentString);
            assertNotNull(contentString);
            assertEquals("books=Les Miserables", contentString);

            assertEquals(200, statusLine.getStatusCode());
            EntityUtils.consume(entity);
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
    }

    /**
     * This test case tests the encryption of JSON payload
     *
     * @throws Exception
     */
    @Test
    public void testJAXRS_jsonEncryption() throws Exception {

        PrivateKey privateKey = getPrivateKey();

        String urlStr = "http://localhost:11080/rest/bookstore/";
        URL url = new URL(urlStr);

        DefaultHttpClient httpclient = null;
        try {

            httpclient = new DefaultHttpClient();

            HttpGet httpget = new HttpGet(url.toExternalForm());

            httpget.setHeader(JWEInterceptor.CLIENT_ID, "1234");

            System.out.println("executing request:" + httpget.getRequestLine());
            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();

            System.out.println("----------------------------------------");
            StatusLine statusLine = response.getStatusLine();
            System.out.println(statusLine);
            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }

            InputStream is = entity.getContent();
            String contentString = getContentAsString(is);

            JSONWebToken jwt = new JSONWebToken();
            jwt.setPrivateKey(privateKey);
            jwt.decode(contentString);

            JSONObject jsonObject = jwt.getData();

            assertNotNull(jsonObject);
            assertEquals("Harry Potter", jsonObject.getString("name"));
            System.out.println(jsonObject.toString());

            assertEquals(200, statusLine.getStatusCode());
            EntityUtils.consume(entity);
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
    }

    private String getContentAsString(InputStream is) throws IOException {
        // read it with BufferedReader
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        StringBuilder sb = new StringBuilder();

        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        return sb.toString();
    }

    private PrivateKey getPrivateKey() throws Exception {
        InputStream is = getClass().getClassLoader().getResourceAsStream("keystore/pbox_jaxrs.keystore");
        assertNotNull(is);
        KeyStore keystore = KeyStoreUtil.getKeyStore(is, "pass123".toCharArray());

        // Get private key
        Key key = keystore.getKey("1234", "pass123".toCharArray());
        return (PrivateKey) key;
    }
}