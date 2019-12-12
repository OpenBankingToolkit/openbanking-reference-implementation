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
package com.forgerock.openbanking.gateway;

import com.github.tomakehurst.wiremock.junit.WireMockClassRule;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.cloud.contract.wiremock.WireMockSpring;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;
import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ForgerockOpenbankingGatewayApplicationJwkmsIT {
    @LocalServerPort
    private int port;
    private WebTestClient webClient;
    @Rule
    public WireMockClassRule jwkmsMock = new WireMockClassRule(WireMockSpring.options().httpsPort(8097).keystorePath("src/test/resources/jwkms.jks").keystorePassword("changeit"));

    @Before
    public void setup() throws SSLException {
        String baseUri = "https://jwkms.dev-ob.forgerock.financial:" + port;

        SslContext sslContext = SslContextBuilder
                .forClient()
                .sslProvider(SslProvider.JDK)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(
                HttpClient.create().secure(t -> t.sslContext(sslContext)

                ));

        this.webClient = WebTestClient.bindToServer(connector).responseTimeout(Duration.ofSeconds(10)).baseUrl(baseUri).build();
    }

    @Test
    public void jwkmsExternalActuatorInfoForwardToInternalActuatorInfo() {
        // Given
        jwkmsMock.stubFor(get(urlEqualTo("/actuator/info"))
                .willReturn(aResponse()
                        .withStatus(200)));

        // When
        webClient.get()
                .uri("/external/actuator/info")
                .exchange()

                // Then
                .expectStatus()
                .isOk();
    }

    @Test
    public void jwkmsExternalActuatorHealthForwardToInternalActuatorHealth() {
        // Given
        jwkmsMock.stubFor(get(urlEqualTo("/actuator/health"))
                .willReturn(aResponse()
                        .withStatus(200)));

        // When
        webClient.get()
                .uri("/external/actuator/health")
                .exchange()

                // Then
                .expectStatus()
                .isOk();
    }

}
