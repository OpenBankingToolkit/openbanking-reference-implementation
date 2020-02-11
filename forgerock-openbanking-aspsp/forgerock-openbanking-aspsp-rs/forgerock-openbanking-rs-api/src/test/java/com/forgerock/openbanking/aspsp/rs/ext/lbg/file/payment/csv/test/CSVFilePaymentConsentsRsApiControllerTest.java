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
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.test;

import com.forgerock.openbanking.am.services.AMResourceServerService;
import com.forgerock.openbanking.aspsp.rs.ForgerockOpenbankingRsApiApplication;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVFilePaymentType;
import com.forgerock.openbanking.common.conf.RSConfiguration;
import com.forgerock.openbanking.common.model.openbanking.forgerock.ConsentStatusCode;
import com.forgerock.openbanking.common.model.openbanking.v3_1.payment.FRFileConsent2;
import com.forgerock.openbanking.common.services.store.RsStoreGateway;
import com.forgerock.openbanking.common.services.store.payment.FilePaymentService;
import com.forgerock.openbanking.constants.OIDCConstants;
import com.forgerock.openbanking.integration.test.support.SpringSecForTest;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.model.OBRIRole;
import com.github.jsonzou.jmockdata.JMockData;
import com.nimbusds.jwt.SignedJWT;
import lombok.val;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import uk.org.openbanking.OBHeaders;
import uk.org.openbanking.datamodel.payment.OBSupplementaryData1;
import uk.org.openbanking.datamodel.payment.OBWriteFileConsent2;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

import static com.forgerock.openbanking.integration.test.support.JWT.jws;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration(classes = {ForgerockOpenbankingRsApiApplication.class})
public class CSVFilePaymentConsentsRsApiControllerTest {

    final static String RESOURCES_PACK = "ext/lbg/file/payment/csv";

    private MockMvc mockMvc;

    @Autowired
    @Order(Ordered.HIGHEST_PRECEDENCE)
    private SpringSecForTest springSecForTest;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @MockBean(name = "amResourceServerService") // Required to avoid Spring auto-wiring exception
    private AMResourceServerService amResourceServerService;

    @MockBean(name = "cryptoApiClient") // Required to avoid Spring auto-wiring exception
    private CryptoApiClient cryptoApiClient;

    @MockBean
    private RsStoreGateway rsStoreGateway;

    @MockBean
    private FilePaymentService filePaymentService;

    @Autowired
    private RSConfiguration rsConfiguration;

    @LocalServerPort
    private int port;

    @Before
    public void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .apply(springSecurity())
                .build();
    }

    /**
     * Integration BACS File payment test <br/>
     * Expected HTTP 201 create code
     * @throws Exception
     */
    @Test
    public void test_BULK_BACS_filePayment_upload() throws Exception {

        // given
        String jws = jws("payments", OIDCConstants.GrantType.CLIENT_CREDENTIAL);
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        given(amResourceServerService.verifyAccessToken("Bearer " + jws)).willReturn(SignedJWT.parse(jws));
        String fileConsentId = UUID.randomUUID().toString();
        String csvFileContent = getContent(CSVFilePaymentConsentsRsApiControllerTest.class.getClassLoader().getResource(RESOURCES_PACK + "/Bulk-BACS-file.csv").getFile());

        OBWriteFileConsent2 consentRequest = mockConsent(csvFileContent, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getFileType());

        FRFileConsent2 existingConsent = mockFileConsent(fileConsentId,csvFileContent, consentRequest);

        given(rsStoreGateway.toRsStore(any(), any(), any(), any(), any())).willReturn(ResponseEntity.status(HttpStatus.CREATED).body(existingConsent));
        given(filePaymentService.getPayment(fileConsentId)).willReturn(existingConsent);

        // then
        MvcResult result = mockMvc.perform(
                MockMvcRequestBuilders
                        .post("https://rs-api:" + port + "/open-banking/v3.1/pisp/file-payment-consents/{ConsentId}/file", fileConsentId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType("text/csv")
                        .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                        .header(OBHeaders.AUTHORIZATION, "Bearer " + jws)
                        .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                        .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                        .header(CONTENT_TYPE, "text/csv")
                        .header(ACCEPT, "application/json")
                        .header("x-ob-client-id", "pispId123")
                        .content(csvFileContent))
                .andExpect(status().isCreated())
                .andReturn();

        Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(201);
    }

    /**
     * Integration Batch File payment test <br/>
     * Expected HTTP 201 create code
     * @throws Exception
     */
    @Test
    public void test_BATCH_FPS_filePayment_upload() throws Exception {

        // given
        String jws = jws("payments", OIDCConstants.GrantType.CLIENT_CREDENTIAL);
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        given(amResourceServerService.verifyAccessToken("Bearer " + jws)).willReturn(SignedJWT.parse(jws));
        String fileConsentId = UUID.randomUUID().toString();
        String csvFileContent = getContent(CSVFilePaymentConsentsRsApiControllerTest.class.getClassLoader().getResource(RESOURCES_PACK + "/Batch-FPS-file.csv").getFile());

        OBWriteFileConsent2 consentRequest = mockConsent(csvFileContent, CSVFilePaymentType.UK_LBG_FPS_BATCH_V10.getFileType());

        FRFileConsent2 existingConsent = mockFileConsent(fileConsentId,csvFileContent, consentRequest);

        given(rsStoreGateway.toRsStore(any(), any(), any(), any(), any())).willReturn(ResponseEntity.status(HttpStatus.CREATED).body(existingConsent));
        given(filePaymentService.getPayment(fileConsentId)).willReturn(existingConsent);

        // then
        MvcResult result = mockMvc.perform(
                MockMvcRequestBuilders
                        .post("https://rs-api:" + port + "/open-banking/v3.1/pisp/file-payment-consents/{ConsentId}/file", fileConsentId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType("text/csv")
                        .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                        .header(OBHeaders.AUTHORIZATION, "Bearer " + jws)
                        .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                        .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                        .header(CONTENT_TYPE, "text/csv")
                        .header(ACCEPT, "application/json")
                        .header("x-ob-client-id", "pispId123")
                        .content(csvFileContent))
                .andExpect(status().isCreated())
                .andReturn();

        Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(201);
    }

    /**
     * Create the consent request object
     * @param csvFileContent
     * @param fileType
     * @return
     */
    private static final OBWriteFileConsent2 mockConsent(String csvFileContent, String fileType){
        OBWriteFileConsent2 consentRequest = JMockData.mock(OBWriteFileConsent2.class);
        consentRequest.getData().getInitiation().fileHash(computeSHA256FullHash(csvFileContent));
        consentRequest.getData().getInitiation().fileReference("FileRef001");
        consentRequest.getData().getInitiation().fileType(fileType);
        consentRequest.getData().getInitiation().numberOfTransactions("3");
        consentRequest.getData().getInitiation().controlSum(new BigDecimal("0.6"));
        consentRequest.getData().getInitiation().localInstrument("Local-instrument");
        consentRequest.getData().getInitiation().supplementaryData(new OBSupplementaryData1());
        return consentRequest;
    }

    /**
     * Create the file payment consent object
     * @param fileConsentId
     * @param csvFileContent
     * @param consentRequest
     * @return
     */
    private static final FRFileConsent2 mockFileConsent(String fileConsentId, String csvFileContent, OBWriteFileConsent2 consentRequest){
        FRFileConsent2 frFileConsent2 = JMockData.mock(FRFileConsent2.class);
        frFileConsent2.setStatus(ConsentStatusCode.AWAITINGAUTHORISATION);
        frFileConsent2.setId(fileConsentId);
        frFileConsent2.setFileContent(csvFileContent);
        frFileConsent2.setPayments(Collections.emptyList());
        frFileConsent2.setWriteFileConsent(consentRequest);
        return frFileConsent2;
    }

    /**
     * Get the file content like a string
     * @param filePath
     * @return String file content
     * @throws IOException
     */
    @Ignore
    private static final String getContent(final String filePath) throws IOException {
        return Files.readString(Paths.get(filePath), StandardCharsets.UTF_8);
    }

    @Ignore
    private static final String computeSHA256FullHash(final String content) {
        try {
            val digest = MessageDigest.getInstance("SHA-256");
            val hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown algorithm for file hash: SHA-256");
        }

    }
}
