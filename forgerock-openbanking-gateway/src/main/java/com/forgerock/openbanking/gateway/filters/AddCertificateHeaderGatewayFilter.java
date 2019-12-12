/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.filters;

import brave.Tracer;
import brave.propagation.TraceContext;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.*;
import java.net.URLDecoder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
@Slf4j
public class AddCertificateHeaderGatewayFilter implements GatewayFilter {
    private static String CLIENT_CERTIFICATE_HEADER_NAME = "x-client-cert";
    private static String CLIENT_CERTIFICATE_PEM_HEADER_NAME = "x-client-pem-cert";
    private static String OB_MONITORING_HEADER_NAME = "x-ob-monitoring";

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    @Value("${gateway.client-jwk-header}")
    private String clientJwkHeader;
    @Value("${monitoring.internal-port}")
    private String monitoringPort;
    @Autowired
    private Tracer tracer;
    @Autowired
    private WebClient webClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        X509Certificate[] certs = request.getSslInfo().getPeerCertificates();

        log.debug("Try to find the client certificate");
        X509Certificate certificate = null;

        String monitoringID = request.getHeaders().getFirst(OB_MONITORING_HEADER_NAME);
        if (monitoringID != null) {
            log.debug("Found the header '{}' equals to {}", OB_MONITORING_HEADER_NAME, monitoringID);
            return getMonitoringCertificate(monitoringID).flatMap(c -> {
                try {
                    JWK jwk = JWK.parse(c);
                    log.debug("Adding the client certificate JWK {} in the header of the request", jwk.toJSONString());
                    return chain.filter(exchange.mutate().request(
                            exchange.getRequest().mutate().header(clientJwkHeader, jwk.toJSONString()).build()
                    ).build());
                }  catch (JOSEException e) {
                    log.error("Can't parse x509 certificate", e);
                    return chain.filter( exchange);
                }
            });
        }

        if (request.getHeaders().getFirst(CLIENT_CERTIFICATE_HEADER_NAME) != null) {
            log.debug("Found a pem in the header '{}'", CLIENT_CERTIFICATE_HEADER_NAME);
            certificate = parseCertificate(request);
        } else if (certs != null && certs.length > 0) {
            log.debug("Extract the certificate from the request");
            certificate =  certs[0];
        } else {
            log.debug("No client certificate received.");
        }

        if (certificate != null) {
            log.debug("Convert the certificate into a JWK");
            try {
                JWK jwk = JWK.parse(certificate);
                log.debug("Adding the client certificate JWK {} in the header of the request", jwk.toJSONString());
                return chain.filter( exchange.mutate().request(
                        exchange.getRequest().mutate()
                                .header(clientJwkHeader, jwk.toJSONString())
                                .header(CLIENT_CERTIFICATE_PEM_HEADER_NAME, serialiseCertificate(certificate).replace("\n", ""))
                                .build()
                ).build());
            } catch (JOSEException e) {
                log.error("Can't parse x509 certificate", e);
            }
        } else {
            log.debug("Client certificate couldn't be exacted for a reason.");
        }
        return chain.filter( exchange);
    }

    private Mono<X509Certificate> getMonitoringCertificate(String monitoringID) {
        return webClient.method(HttpMethod.GET)
            .uri("https://monitoring:" + monitoringPort + "/api/test/software-statement/"+ monitoringID + "/certificate")
            .retrieve().bodyToMono(String.class)
                    .flatMap(c -> Mono.just(parseCertificate(c)));
    }

    public X509Certificate parseCertificate(ServerHttpRequest request) {
        String certStr = request.getHeaders().getFirst(CLIENT_CERTIFICATE_HEADER_NAME);
        try {
            return parseCertificate(URLDecoder.decode(certStr, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            log.error("Couldn't decode the header", e);
        }
        return null;
    }


    private X509Certificate parseCertificate(String certStr) {
        //before decoding we need to get rod off the prefix and suffix
        log.debug("Client certificate as PEM format: \n {}", certStr);

        try {

            byte [] decoded = Base64.getDecoder()
                    .decode(
                            certStr
                                    .replaceAll("\n", "")
                                    .replaceAll(BEGIN_CERT, "")
                                    .replaceAll(END_CERT, ""));
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
        } catch (CertificateException e) {
            log.error("Can't initialise certificate factory", e);
        }
        return null;
    }

    private String serialiseCertificate(X509Certificate certificate) {
        PrintStream ps = null;
        ByteArrayOutputStream bs = null;
        try {

            bs = new ByteArrayOutputStream();
            ps = new PrintStream(bs);

            ps.println(BEGIN_CERT);
            ps.println(new String(Base64.getEncoder().encode(certificate.getEncoded())));
            ps.println(END_CERT);
            return new String(bs.toByteArray());
        } catch (CertificateEncodingException e) {
            log.error("Couldn't encode certificate", e);
            return null;
        } finally {
            if (ps != null) {
                ps.close();
            }
            if (bs != null) {
                try {
                    bs.close();
                } catch (IOException e) {
                    log.error("Couldn't close properly ByteArrayOutputStream", e);
                }
            }
        }
    }
}
