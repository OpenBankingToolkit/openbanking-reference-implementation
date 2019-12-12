/**
 * Copyright 2019 ForgeRock AS.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.openbanking.gateway.config;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
public class SslConfiguration {

    private static final String JAVA_KEYSTORE = "jks";

    @Value("${server.ssl.key-store}")
    private Resource keyStore;
    @Value("${server.ssl.key-store-password}")
    private String keyStorePassword;
    @Value("${server.ssl.key-password}")
    private String keyPassword;
    @Value("${server.ssl.enabled}")
    private boolean sslEnabled;

    public HttpComponentsClientHttpRequestFactory factory(String keyAlias, boolean checkHostname) throws SslConfigurationFailure {
        try {
            SSLContextBuilder sslContextBuilder;
            if (sslEnabled) {
                sslContextBuilder = new SSLContextBuilder()
                        .loadKeyMaterial(
                                getStore(keyStore.getURL(), keyStorePassword.toCharArray()),
                                keyPassword.toCharArray(),
                                (aliases, socket) -> keyAlias
                        );
            } else {
                sslContextBuilder = org.apache.http.ssl.SSLContexts.custom();
            }

            SSLContext sslContext = sslContextBuilder.build();
            SSLConnectionSocketFactory socketFactory;

            if (checkHostname) {
                socketFactory = new SSLConnectionSocketFactory(sslContext);
            } else {
                socketFactory = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
            }

            HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build();
            return new HttpComponentsClientHttpRequestFactory(httpClient);
        } catch (Exception e) {
            throw new SslConfigurationFailure(e);
        }
    }

    protected KeyStore getStore(final URL url, final char[] password) throws
            KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore store = KeyStore.getInstance(JAVA_KEYSTORE);
        InputStream inputStream = url.openStream();
        try {
            store.load(inputStream, password);
        } finally {
            inputStream.close();
        }

        return store;
    }
}
