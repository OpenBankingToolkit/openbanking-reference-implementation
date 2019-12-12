/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.filters;

import com.forgerock.openbanking.gateway.model.Tpp;
import com.forgerock.openbanking.gateway.services.AuthenticationService;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.support.BodyInserterContext;
import org.springframework.cloud.gateway.support.CachedBodyOutputMessage;
import org.springframework.cloud.gateway.support.DefaultServerRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Level;
import java.util.stream.Collectors;

@Configuration
@Slf4j
public class AccessTokenGatewayFilter implements GatewayFilter {

    @Autowired
    private AuthenticationService authenticationService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String TEST_ATTRIBUTE = "read_body_predicate_test_attribute";
        final String TEST_MESSAGE_ATTRIBUTE = "read_body_predicate_test_message_attribute";
        ServerRequest serverRequest = new DefaultServerRequest(exchange);
        ServerHttpRequest request = exchange.getRequest();
        final Optional<Tpp> isTpp = authenticationService.authenticateTPP(request);

        Mono<LinkedMultiValueMap> modifiedBody = serverRequest.bodyToMono(LinkedMultiValueMap.class)
                .log("AccessTokenGatewayFilter", Level.INFO)
                .flatMap(accessTokenRequest -> {
                    if (isTpp.isPresent()) {
                        Tpp tpp = isTpp.get();
                        String clientIDFromRequest = null;
                        if (accessTokenRequest.get("client_assertion") != null) {
                            String clientAssertion = (String) accessTokenRequest.get("client_assertion").get(0);
                            log.debug("Read client ID from client assertion found: {}", clientAssertion);
                            try {
                                SignedJWT jws = (SignedJWT) JWTParser.parse(clientAssertion);
                                clientIDFromRequest = jws.getJWTClaimsSet().getSubject();
                            } catch (ParseException e) {
                                log.error("Parse client assertion error", e);
                            }
                        } else if (request.getHeaders().getFirst("Authorization") != null) {
                            String authorisation = request.getHeaders().getFirst("Authorization");
                            log.debug("Read client ID from client authorisation header: {}", authorisation);
                            clientIDFromRequest = clientIDFromBasic(authorisation);
                        } else if (accessTokenRequest.get("client_id") != null) {
                            log.debug("Read client ID from client body parameter 'client_id'");
                            clientIDFromRequest = (String) accessTokenRequest.get("client_id").get(0);
                        }

                        log.debug("Client ID found in the request: {}", clientIDFromRequest);

                        if (clientIDFromRequest == null) {
                            exchange.getAttributes().put(TEST_ATTRIBUTE, false);
                            exchange.getAttributes().put(TEST_MESSAGE_ATTRIBUTE,
                                    "No credential found in the request. " +
                                            "Use the appropriate token authentication method to send your TPP credential, like client certificate assertion.");
                        } else if (tpp.getClientId().equals(clientIDFromRequest)) {
                            exchange.getAttributes().put(TEST_ATTRIBUTE, true);
                        } else {
                            exchange.getAttributes().put(TEST_ATTRIBUTE, false);
                            exchange.getAttributes().put(TEST_MESSAGE_ATTRIBUTE,
                                    "Software statement behind transport certificate '" + tpp.getClientId()
                                            + "' doesn't match the one specified in the request '" + clientIDFromRequest + "'");
                        }
                    } else {
                        exchange.getAttributes().put(TEST_ATTRIBUTE, false);
                        exchange.getAttributes().put(TEST_MESSAGE_ATTRIBUTE,
                                "Invalid transport certificate: no software statement found");
                    }
                    return Mono.just(accessTokenRequest);
                });

        BodyInserter bodyInserter = BodyInserters.fromPublisher(modifiedBody, LinkedMultiValueMap.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.putAll(exchange.getRequest().getHeaders().entrySet().stream()
                .collect(Collectors.toMap(x -> x.getKey(), x -> x.getValue())));

        CachedBodyOutputMessage outputMessage = new CachedBodyOutputMessage(exchange, httpHeaders);

        return bodyInserter.insert(outputMessage, new BodyInserterContext())
                .then(Mono.defer(() -> {
                    boolean isAuthenticated = (Boolean) exchange.getAttributes()
                            .getOrDefault(TEST_ATTRIBUTE, Boolean.FALSE);
                    String message = (String) exchange.getAttributes()
                            .getOrDefault(TEST_MESSAGE_ATTRIBUTE, "");
                    if (!isAuthenticated) {
                        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
                        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().writeWith(Flux.just(buffer));
                    }
                    exchange.getAttributes().remove(TEST_ATTRIBUTE);
                    exchange.getAttributes().remove(TEST_MESSAGE_ATTRIBUTE);

                    ServerHttpRequestDecorator decorator = new ServerHttpRequestDecorator(
                            exchange.getRequest()) {
                        @Override
                        public HttpHeaders getHeaders() {
                            HttpHeaders httpHeaders = new HttpHeaders();
                            httpHeaders.putAll(super.getHeaders()
                                    .entrySet().stream()
                                    .collect(Collectors.toMap(x -> x.getKey(), x -> x.getValue())));
                            ;
                            httpHeaders.set(HttpHeaders.TRANSFER_ENCODING, "chunked");
                            return httpHeaders;
                        }

                        @Override
                        public Flux<DataBuffer> getBody() {
                            return outputMessage.getBody();
                        }
                    };

                    return chain.filter(exchange.mutate().request(decorator).build());
                }));
    }

    private String clientIDFromBasic(String authorization) {
        if (authorization != null && authorization.startsWith("Basic")) {
            // Authorization: Basic base64credentials
            String base64Credentials = authorization.substring("Basic".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials),
                    Charset.forName("UTF-8"));
            // credentials = username:password
            final String[] values = credentials.split(":", 2);
            return values[0];
        }
        return null;
    }
}
