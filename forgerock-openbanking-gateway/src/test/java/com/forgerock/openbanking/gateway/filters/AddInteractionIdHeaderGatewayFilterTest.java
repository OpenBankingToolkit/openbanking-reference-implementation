/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.filters;

import brave.Span;
import brave.Tracer;
import brave.propagation.TraceContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@RunWith(MockitoJUnitRunner.class)
public class AddInteractionIdHeaderGatewayFilterTest {
    @Mock
    private Tracer tracer;

    @InjectMocks
    private AddInteractionIdHeaderGatewayFilter addInteractionIdHeaderGatewayFilter;

    private GatewayFilterChain chain;

    @Before
    public void setup() {
        Span span = mock(Span.class);
        given(tracer.currentSpan()).willReturn(span);
        given(span.context()).willReturn(TraceContext.newBuilder().traceId(1L).spanId(1L).build());

        chain = mock(GatewayFilterChain.class);
        given(chain.filter(any())).willReturn(Mono.empty());
    }

    @Test
    public void filter_provideValidInteractionId() {
        // Given
        HttpHeaders responseHeaders = new HttpHeaders();
        String interactionId = UUID.randomUUID().toString();
        ServerWebExchange exchange = setupRequestWithInteractionId(interactionId, responseHeaders);

        // When
        addInteractionIdHeaderGatewayFilter.filter(exchange, chain);

        // Then
        assertThat(interactionId).isEqualTo(responseHeaders.getFirst("x-fapi-interaction-id"));
    }

    @Test
    public void filter_provideNoInteractionId_getGeneratedOne() {
        // Given
        HttpHeaders responseHeaders = new HttpHeaders();
        String interactionId = "";
        ServerWebExchange exchange = setupRequestWithInteractionId(interactionId, responseHeaders);

        // When
        addInteractionIdHeaderGatewayFilter.filter(exchange, chain);

        // Then
        assertThat(responseHeaders.getFirst("x-fapi-interaction-id")).isNotNull();
    }

    @Test
    public void filter_provideInvalidInteractionId_error() {
        // Given
        HttpHeaders responseHeaders = new HttpHeaders();
        String interactionId = "abc<script>123";
        ServerWebExchange exchange = setupRequestWithInteractionId(interactionId, responseHeaders);

        // When
        Mono<Void> resp = addInteractionIdHeaderGatewayFilter.filter(exchange, chain);

        // Then
        assertThat(resp.toString()).isEqualTo("MonoError");
    }

    private ServerWebExchange setupRequestWithInteractionId(String interactionId,  HttpHeaders responseHeaders) {
        ServerWebExchange exchange = mock(ServerWebExchange.class);
        ServerHttpRequest serverHttpRequest = mock(ServerHttpRequest.class);
        ServerHttpResponse serverHttpResponse = mock(ServerHttpResponse.class);

        ServerWebExchange.Builder builder = mock(ServerWebExchange.Builder.class);
        given(exchange.mutate()).willReturn(builder);
        given(builder.request(any(ServerHttpRequest.class))).willReturn(builder);
        given(builder.build()).willReturn(exchange);

        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.add("x-fapi-interaction-id", interactionId);
        given(exchange.getRequest()).willReturn(serverHttpRequest);
        given(exchange.getResponse()).willReturn(serverHttpResponse);
        given(serverHttpRequest.getHeaders()).willReturn(requestHeaders);
        given(serverHttpResponse.getHeaders()).willReturn(responseHeaders);

        ServerHttpRequest.Builder reqBuilder = mock(ServerHttpRequest.Builder.class);
        given(serverHttpRequest.mutate()).willReturn(reqBuilder);
        given(reqBuilder.header(anyString(), anyString())).willReturn(reqBuilder);
        given(reqBuilder.build()).willReturn(serverHttpRequest);

        return exchange;
    }


}