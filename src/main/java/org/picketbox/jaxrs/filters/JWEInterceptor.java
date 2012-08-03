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
package org.picketbox.jaxrs.filters;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.security.KeyStore;
import java.security.PublicKey;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;
import org.json.JSONObject;
import org.picketbox.core.util.KeyStoreUtil;
import org.picketbox.jaxrs.PicketBoxJAXRSMessages;
import org.picketbox.jaxrs.wrappers.ResponseWrapper;
import org.picketbox.json.exceptions.ProcessingException;
import org.picketbox.json.token.JSONWebToken;

/**
 * <p>
 * A {@link Filter} that is used to encrypt outgoing JSON payloads
 * </p>
 * <p>
 * Configuration: <br/>
 * <UL>
 * <LI>keystore : url of the keystore</LI>
 * <LI>storepass : store pass of the keystore</LI>
 * </UL>
 *
 * @author anil saldhana
 * @since Aug 3, 2012
 */
public class JWEInterceptor implements Filter {
    public static final String CLIENT_ID = "CLIENT_ID";
    protected FilterConfig theConfig;

    protected KeyStore keystore = null;

    public static final String HEADER = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC\",\"int\":\"HS256\",\"iv\":\"48V1_ALb6US04U3b\"}";

    String keyStorePass = null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.theConfig = filterConfig;
        String keyStoreURL = filterConfig.getInitParameter("keystore");
        keyStorePass = filterConfig.getInitParameter("storepass");
        if (keyStoreURL == null) {
            keyStoreURL = SecurityActions.getSystemProperty("javax.net.ssl.keyStore", null);
        }
        if (keyStorePass == null) {
            keyStorePass = SecurityActions.getSystemProperty("javax.net.ssl.keyStorePassword", null);
        }
        try {
            InputStream is = this.getKeyStoreInputStream(keyStoreURL);
            keystore = KeyStoreUtil.getKeyStore(is, keyStorePass.toCharArray());
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        String clientId = null;
        ServletResponse wrappedResponse = response;
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            clientId = httpRequest.getHeader(CLIENT_ID);
        }

        try {
            if (request instanceof HttpServletRequest) {
                wrappedResponse = new ResponseWrapper((HttpServletResponse) response);
            }
            chain.doFilter(request, wrappedResponse);
        } finally {

            if (wrappedResponse instanceof ResponseWrapper) {
                ResponseWrapper wrapper = (ResponseWrapper) wrappedResponse;
                PrintWriter writer = wrapper.getWriter();
                ByteArrayOutputStream baos = (ByteArrayOutputStream) wrapper.getByteArrayOutputStream();
                String contentType = response.getContentType();
                if (contentType != null && contentType.contains("application/json")) {
                    JSONWebToken webToken = new JSONWebToken();
                    try {
                        webToken.setData(new JSONObject(new String(baos.toByteArray())));
                        webToken.setHeader(new JSONObject(HEADER));
                    } catch (JSONException e) {
                        throw PicketBoxJAXRSMessages.MESSAGES.servletException(e);
                    }
                    webToken.setPublicKey(getPublicKey(clientId));
                    try {
                        String encodedString = webToken.encode();
                        writer.write(encodedString);
                        writer.flush();
                        writer.close();
                    } catch (ProcessingException e) {
                        throw PicketBoxJAXRSMessages.MESSAGES.servletException(e);
                    }
                } else {
                    writer.write(new String(baos.toByteArray()));
                }
            }
        }
    }

    @Override
    public void destroy() {
    }

    /**
     * Given a Client ID, get the {@link PublicKey} from the keystore
     *
     * @param clientID
     * @return
     */
    private PublicKey getPublicKey(String clientID) {
        try {
            return KeyStoreUtil.getPublicKey(keystore, clientID, keyStorePass.toCharArray());
        } catch (Exception e) {
            throw PicketBoxJAXRSMessages.MESSAGES.publicKeyRetrievalException(e);
        }
    }

    /**
     * Seek the input stream to the KeyStore
     *
     * @param keyStore
     * @return
     */
    private InputStream getKeyStoreInputStream(String keyStore) {
        InputStream is = null;

        try {
            // Try the file method
            File file = new File(keyStore);
            is = new FileInputStream(file);
        } catch (Exception e) {
            URL url = null;
            try {
                url = new URL(keyStore);
                is = url.openStream();
            } catch (Exception ex) {
                url = SecurityActions.loadResource(getClass(), keyStore);
                if (url != null) {
                    try {
                        is = url.openStream();
                    } catch (IOException e1) {
                    }
                }
            }
        }

        if (is == null) {
            // Try the user.home dir
            String userHome = SecurityActions.getSystemProperty("user.home", "") + "/picketbox-keystore";
            File ksDir = new File(userHome);
            if (ksDir.exists()) {
                try {
                    is = new FileInputStream(new File(userHome + "/" + keyStore));
                } catch (FileNotFoundException e) {
                    is = null;
                }
            }
        }
        if (is == null)
            throw PicketBoxJAXRSMessages.MESSAGES.invalidNullArgument("KeyStore InputStream");
        return is;
    }
}