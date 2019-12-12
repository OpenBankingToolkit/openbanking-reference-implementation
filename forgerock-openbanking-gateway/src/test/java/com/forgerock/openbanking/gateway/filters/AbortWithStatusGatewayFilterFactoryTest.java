/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
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