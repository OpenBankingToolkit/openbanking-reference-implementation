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

import brave.handler.FinishedSpanHandler;
import brave.handler.MutableSpan;
import brave.propagation.TraceContext;
import com.forgerock.openbanking.gateway.config.SslConfiguration;
import com.forgerock.openbanking.gateway.config.SslConfigurationFailure;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.http.codec.support.DefaultServerCodecConfigurer;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
@EnableDiscoveryClient
@Import(GatewayRouteLocatorConfiguration.class)
public class ForgerockOpenbankingGatewayApplication {

    @Value("${server.ssl.client-certs-key-alias}")
    private String keyAlias;

    @Value("${dns.hosts.root}")
    private String dnsHostRoot;

    public static void main(String[] args) {
        SpringApplication.run(ForgerockOpenbankingGatewayApplication.class, args);
    }

    @Bean
    public WebClient webClient() {
        return WebClient.create();
    }

    @Bean
    @LoadBalanced
    public RestTemplate restTemplate(SslConfiguration sslConfiguration) throws SslConfigurationFailure {
        return new RestTemplate(sslConfiguration.factory(keyAlias, false));
    }

    @Bean
    @Primary
    public ServerCodecConfigurer serverCodecConfigurer() {
        return new DefaultServerCodecConfigurer();
    }

    @Bean
    FinishedSpanHandler addClusterDomainHandler() {
        return new FinishedSpanHandler() {
            @Override
            public boolean handle(TraceContext traceContext, MutableSpan span) {
                span.tag("clusterDomain", dnsHostRoot);
                return true;
            }
        };
    }
}
