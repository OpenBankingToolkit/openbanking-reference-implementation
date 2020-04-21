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
package com.forgerock.openbanking.common;

import com.forgerock.openbanking.model.error.ClientResponseErrorHandler;
import com.forgerock.openbanking.ssl.config.SslConfiguration;
import com.forgerock.openbanking.ssl.exceptions.SslConfigurationFailure;
import io.netty.handler.ssl.SslContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.util.List;

/**
 * A centralised configuration for client SSL related concerns, including a universal {@link RestTemplate}.
 */
@Configuration
class SslClientConfiguration {

    @Autowired
    private SslConfiguration sslConfiguration;
    @Value("${server.ssl.client-certs-key-alias}")
    private String keyAlias;

    @Bean
    public RestTemplate restTemplate(@Qualifier("mappingJacksonHttpMessageConverter") MappingJackson2HttpMessageConverter converter) throws SslConfigurationFailure {
        RestTemplate restTemplate = new RestTemplate(sslConfiguration.factory(keyAlias, true));
        customiseRestTemplate(converter, restTemplate);
        return restTemplate;
    }

    private void customiseRestTemplate(@Qualifier("mappingJacksonHttpMessageConverter") MappingJackson2HttpMessageConverter converter, RestTemplate restTemplate) {
        List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
        messageConverters.removeIf(c -> c instanceof MappingJackson2HttpMessageConverter);
        messageConverters.add(converter);
        restTemplate.setErrorHandler(new ClientResponseErrorHandler());
    }

    @Bean
    public MappingJackson2HttpMessageConverter mappingJacksonHttpMessageConverter(@Qualifier("objectMapperBuilderCustomizer") Jackson2ObjectMapperBuilderCustomizer objectMapperBuilderCustomizer) {
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();
        objectMapperBuilderCustomizer.customize(objectMapperBuilder);
        converter.setObjectMapper(objectMapperBuilder.build());
        return converter;
    }

    @Bean
    public WebClient webClient() throws Exception {
        SslContext sslContext = sslConfiguration.getSslContextForReactor(keyAlias);
        HttpClient httpClient = HttpClient.create()
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        return WebClient.builder().clientConnector(connector).build();
    }

}
