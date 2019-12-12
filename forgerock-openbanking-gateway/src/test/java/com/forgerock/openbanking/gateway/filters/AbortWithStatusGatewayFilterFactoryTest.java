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
package com.forgerock.openbanking.gateway.filters;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.SetStatusGatewayFilterFactory;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;

@RunWith(MockitoJUnitRunner.class)
public class AbortWithStatusGatewayFilterFactoryTest {

    @InjectMocks
    private AbortWithStatusGatewayFilterFactory filter;

    @Test
    public void shouldRaiseExceptionWithNotFound() {
        // Given
        SetStatusGatewayFilterFactory.Config config = new SetStatusGatewayFilterFactory.Config();
        config.setStatus("404");
        ServerWebExchange serverWebExchange = Mockito.mock(ServerWebExchange.class, RETURNS_DEEP_STUBS);
        GatewayFilter filter = this.filter.apply(config);

        // When
        Mono<Void> mono = filter.filter(serverWebExchange, null);

        // Then
        StepVerifier.create(mono)
                .expectError(ResponseStatusException.class)
                .verify();
        assertThatThrownBy(() -> StepVerifier.create(mono)
                .expectComplete()
                .verify())
                .hasMessageContaining("404");
    }
}