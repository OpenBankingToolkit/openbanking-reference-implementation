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
package com.forgerock.openbanking.forgerockopenbankingadmin;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import de.codecentric.boot.admin.server.config.EnableAdminServer;
import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import de.codecentric.boot.admin.server.web.client.InstanceExchangeFilterFunction;
import de.codecentric.boot.admin.server.web.client.InstanceWebClient;
import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.ReadTimeoutHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.ConnectionObserver;
import reactor.netty.http.client.HttpClient;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

@EnableAdminServer
@EnableDiscoveryClient
@SpringBootApplication(scanBasePackages = {"com.forgerock"})
public class ForgerockOpenbankingAdminApplication {

	public static void main(String[] args) {
		SpringApplication.run(ForgerockOpenbankingAdminApplication.class, args);
	}

	@Value("${server.ssl.key-store}")
	private Resource keyStoreResources;
	@Value("${server.ssl.key-store-password}")
	private String keyStorePassword;
	@Value("${server.ssl.key-password}")
	private String keyPassword;
	@Value("${server.ssl.client-certs-key-alias}")
	private String keyAlias;
	@Value("${server.ssl.enabled}")
	private boolean sslEnabled;
	@Autowired
	private AdminServerProperties adminServerProperties;


	private static final String JAVA_KEYSTORE = "jks";

	protected static KeyStore getStore(final URL url, final char[] password) throws
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


	@Bean
	@Primary
	public InstanceWebClient instanceWebClient(HttpHeadersProvider httpHeadersProvider,
											   ObjectProvider<List<InstanceExchangeFilterFunction>> filtersProvider) {
		try {
			KeyStore keyStore = getStore(this.keyStoreResources.getURL(), keyStorePassword.toCharArray());
			Certificate certificate = keyStore.getCertificate(keyAlias);
			Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());

			List<InstanceExchangeFilterFunction> additionalFilters = filtersProvider.getIfAvailable(Collections::emptyList);

			return InstanceWebClient.builder()
					.webClient(createDefaultWebClient((X509Certificate) certificate, (PrivateKey) key,
							adminServerProperties.getMonitor().getConnectTimeout(),
							adminServerProperties.getMonitor().getReadTimeout()))
					.connectTimeout(adminServerProperties.getMonitor().getConnectTimeout())
					.readTimeout(adminServerProperties.getMonitor().getReadTimeout())
					.defaultRetries(adminServerProperties.getMonitor().getDefaultRetries())
					.retries(adminServerProperties.getMonitor().getRetries())
					.httpHeadersProvider(httpHeadersProvider)
					.filters(filters -> filters.addAll(additionalFilters))
					.build();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static WebClient createDefaultWebClient(X509Certificate certificate,
													PrivateKey key,
													Duration connectTimeout,
													Duration readTimeout) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {

		SslContextBuilder sslContextBuilder = SslContextBuilder
				.forClient()
				.keyManager(key, certificate);

		SslContext sslContext = sslContextBuilder.build();

		HttpClient httpClient = HttpClient.create()
				.secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
				.compress(true)
				.tcpConfiguration(tcp -> tcp.bootstrap(bootstrap -> bootstrap.option(
						ChannelOption.CONNECT_TIMEOUT_MILLIS,
						(int) connectTimeout.toMillis()
				)).observe((connection, newState) -> {
					if (ConnectionObserver.State.CONNECTED.equals(newState)) {
						connection.addHandlerLast(new ReadTimeoutHandler(readTimeout.toMillis(),
								TimeUnit.MILLISECONDS
						));
					}
				}));
		ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
		return WebClient.builder().clientConnector(connector).build();
	}


}
