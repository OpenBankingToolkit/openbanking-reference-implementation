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
package com.forgerock.openbanking.aspsp.rs.simulator;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.model.Tpp;
import com.forgerock.openbanking.model.error.ClientResponseErrorHandler;
import com.forgerock.openbanking.ssl.config.SslConfiguration;
import com.forgerock.openbanking.ssl.exceptions.SslConfigurationFailure;
import com.forgerock.openbanking.ssl.services.keystore.KeyStoreService;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.X509Collector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import io.netty.handler.ssl.SslContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@EnableWebSecurity

@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
public class SimulatorApplication {

    /**
	 * Set to 'false' to stop any of the scheduled tasks running. Defaults to 'true' if property not present.
	 */
	public static final String RUN_SCHEDULED_TASK_PROPERTY = "simulator.runScheduledTasks";

	public static void main(String[] args) {
        SpringApplication.run(SimulatorApplication.class, args);
    }


	@Value("${matls.forgerock-internal-ca-alias}")
	private String internalCaAlias;
	@Value("${matls.forgerock-external-ca-alias}")
	private String externalCaAlias;
	@Autowired
	private SslConfiguration sslConfiguration;
	@Value("${server.ssl.client-certs-key-alias}")
	private String keyAlias;

	private static String getCn(X509Certificate x509Certificate) {
		try {
			X500Name x500name = new JcaX509CertificateHolder(x509Certificate).getSubject();
			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			return IETFUtils.valueToString(cn.getFirst().getValue());
		} catch (CertificateEncodingException e) {
			return null;
		}
	}

	@Configuration
	static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
		private static String CLIENT_CERTIFICATE_HEADER_NAME = "x-client-jwk";

		@Autowired
		private KeyStoreService keyStoreService;
		@Value("${matls.forgerock-internal-ca-alias}")
		private String internalCaAlias;
		@Value("${matls.forgerock-external-ca-alias}")
		private String externalCaAlias;
		@Value("${openbankingdirectory.certificates.ob.root}")
		private Resource obRootCertificatePem;
		@Value("${openbankingdirectory.certificates.ob.issuing}")
		private Resource obIssuingCertificatePem;

		private X509Certificate[] obCA;

		@Autowired
		private TppStoreService tppStoreService;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			loadOBCertificates();
			X509Certificate internalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(internalCaAlias);
			X509Certificate externalCACertificate = (X509Certificate) keyStoreService.getKeyStore().getCertificate(externalCaAlias);

			OBRIInternalCertificates obriInternalCertificates = new OBRIInternalCertificates(internalCACertificate);
			OBRIExternalCertificates obriExternalCertificates = new OBRIExternalCertificates(externalCACertificate, tppStoreService, obCA);

			http

					.csrf().disable()
					.authorizeRequests()
					.anyRequest()
					.permitAll()//.authenticated()
					.and()
					.authenticationProvider(new CustomAuthProvider())
					.apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
							.collector(PSD2Collector.psd2Builder()
									.collectFromHeader(CertificateHeaderFormat.JWK)
									.headerName(CLIENT_CERTIFICATE_HEADER_NAME)
									.usernameCollector(obriInternalCertificates)
									.authoritiesCollector(obriInternalCertificates)
									.build())
							.collector(PSD2Collector.psd2Builder()
									.collectFromHeader(CertificateHeaderFormat.JWK)
									.headerName(CLIENT_CERTIFICATE_HEADER_NAME)
									.usernameCollector(obriExternalCertificates)
									.authoritiesCollector(obriExternalCertificates)
									.build())
							.collector(StaticUserCollector.builder()
									.grantedAuthorities(Collections.emptySet())
									.usernameCollector(() -> "Anonymous")
									.build())
					);
		}

		private void loadOBCertificates() throws CertificateException, IOException {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			InputStream rootCertStream = null;
			InputStream issuingCertStream = null;
			try {
				rootCertStream = obRootCertificatePem.getURL().openStream();
				X509Certificate obRootCert = (X509Certificate) fact.generateCertificate(rootCertStream);

				issuingCertStream = obIssuingCertificatePem.getURL().openStream();
				X509Certificate obIssuingCert = (X509Certificate) fact.generateCertificate(issuingCertStream);
				obCA = new X509Certificate[2];
				obCA[0] = obIssuingCert;
				obCA[1] = obRootCert;
			} finally {
				if (rootCertStream != null) {
					rootCertStream.close();
				}
				if (issuingCertStream != null) {
					issuingCertStream.close();
				}
			}
		}
	}

	@Slf4j
	@AllArgsConstructor
	public static class OBRIInternalCertificates implements PSD2Collector.AuthoritiesCollector, X509Collector.UsernameCollector {

		private X509Certificate caCertificate;

		@Override
		public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
			Set<GrantedAuthority> authorities = new HashSet<>();

			if (roles != null) {
				authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
			}

			if (isCertificateIssuedByCA(certificatesChain)) {
				authorities.add(OBRIRole.ROLE_FORGEROCK_INTERNAL_APP);
			}
			return authorities;
		}

		@Override
		public String getUserName(X509Certificate[] certificatesChain) {
			if (!isCertificateIssuedByCA(certificatesChain)) {
				return null;
			}
			return getCn(certificatesChain[0]);
		}

		private boolean isCertificateIssuedByCA(X509Certificate[] certificatesChain) {
			return (certificatesChain.length > 1 && caCertificate.equals(certificatesChain[1]))
					|| (certificatesChain.length == 1 && caCertificate.getSubjectX500Principal().equals(certificatesChain[0].getIssuerX500Principal()));
		}
	}

	@Slf4j
	@AllArgsConstructor
	public static class OBRIExternalCertificates implements PSD2Collector.AuthoritiesCollector, X509Collector.UsernameCollector {

		private X509Certificate caCertificate;
		private TppStoreService tppStoreService;
		private X509Certificate[] obCA;

		@Override
		public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
			Set<GrantedAuthority> authorities = new HashSet<>();

			if (roles != null) {
				authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
				authorities.add(OBRIRole.ROLE_TPP);
				authorities.add(OBRIRole.ROLE_EIDAS);
			}

			if (isCertificateIssuedByCA(certificatesChain)) {
				authorities.add(OBRIRole.ROLE_FORGEROCK_EXTERNAL_APP);
				authorities.add(OBRIRole.ROLE_TPP);
			}
			if (isCertificateIssuedByCA(obCA)) {
				authorities.add(OBRIRole.ROLE_TPP);
			}

			if (authorities.contains(OBRIRole.ROLE_TPP)) {
				String cn = getCn(certificatesChain[0]);
				Optional<Tpp> optionalTpp = tppStoreService.findByCn(cn);
				if (!optionalTpp.isPresent()) {
					log.debug("TPP not found. This TPP {} is not on board yet", cn);
					authorities.add(OBRIRole.UNREGISTERED_TPP);
				} else {
					List<GrantedAuthority> tppAuthorities = optionalTpp.get().getTypes().stream().map(OBRIRole::fromSoftwareStatementType).collect(Collectors.toList());
					authorities.addAll(tppAuthorities);
				}
			}
			return authorities;
		}

		@Override
		public String getUserName(X509Certificate[] certificatesChain) {
			if (!isCertificateIssuedByCA(certificatesChain)) {
				return null;
			}

			String cn = getCn(certificatesChain[0]);

			Optional<Tpp> optionalTpp = tppStoreService.findByCn(cn);
			if (!optionalTpp.isPresent()) {
				log.debug("TPP not found. This TPP {} is not on board yet", cn);
				return cn;
			} else {
				return optionalTpp.get().getClientId();
			}
		}

		private boolean isCertificateIssuedByCA(X509Certificate[] certificatesChain) {
			return (certificatesChain.length > 1 && caCertificate.equals(certificatesChain[1]))
					|| (certificatesChain.length == 1 && caCertificate.getSubjectX500Principal().equals(certificatesChain[0].getIssuerX500Principal()));
		}
	}

	public static class CustomAuthProvider implements AuthenticationProvider {
		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			//You can load more GrantedAuthority based on the user subject, like loading the TPP details from the software ID
			return authentication;
		}

		@Override
		public boolean supports(Class<?> aClass) {
			return true;
		}
	}

	@Bean
	public RestTemplate restTemplate(@Qualifier("mappingJacksonHttpMessageConverter")
											 MappingJackson2HttpMessageConverter converter) throws SslConfigurationFailure {
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
