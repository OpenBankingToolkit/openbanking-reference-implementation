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
package com.forgerock.openbanking.extensions.lbg.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVFilePaymentType;
import com.forgerock.openbanking.aspsp.rs.store.ForgerockOpenbankingRsStoreApplication;
import com.forgerock.openbanking.aspsp.rs.store.repository.TppRepository;
import com.forgerock.openbanking.aspsp.rs.store.repository.v3_1.payments.FileConsent2Repository;
import com.forgerock.openbanking.common.conf.RSConfiguration;
import com.forgerock.openbanking.common.model.openbanking.forgerock.ConsentStatusCode;
import com.forgerock.openbanking.common.model.openbanking.v3_1.payment.FRFileConsent2;
import com.forgerock.openbanking.common.model.version.OBVersion;
import com.forgerock.openbanking.integration.test.support.SpringSecForTest;
import com.forgerock.openbanking.model.OBRIRole;
import com.github.jsonzou.jmockdata.JMockData;
import kong.unirest.*;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
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
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import uk.org.openbanking.OBHeaders;
import uk.org.openbanking.datamodel.payment.*;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration(classes = ForgerockOpenbankingRsStoreApplication.class)
public class CSVFilePaymentConsentsRsStoreApiControllerTest {

    final static String RESOURCES_PACK = "extensions/lgb/file/payment/csv";

    @LocalServerPort
    private int port;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private RSConfiguration rsConfiguration;
    @Autowired
    private FileConsent2Repository repository;
    @MockBean
    private TppRepository tppRepository;

    @Autowired
    @Order(Ordered.HIGHEST_PRECEDENCE)
    private SpringSecForTest springSecForTest;

    @Before
    public void setUp() {
        Unirest.config().setObjectMapper(new JacksonObjectMapper(objectMapper)).verifySsl(false);
    }

    /**
     * Expected http 201 code
     * @throws UnirestException
     */
    @Test
    public void testCreateFileConsentAllFields() throws UnirestException {
        // Given
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        MockTppHelper.setupMockTpp(tppRepository);
        OBWriteFileConsent2 consentRequest = JMockData.mock(OBWriteFileConsent2.class);
        consentRequest.getData().getInitiation().fileHash("dslkjdslkfhsdlkfjlskdj");
        consentRequest.getData().getInitiation().fileReference("Batch-001");
        consentRequest.getData().getInitiation().fileType(CSVFilePaymentType.UK_LBG_FPS_BATCH_V10.getFileType());
        consentRequest.getData().getInitiation().numberOfTransactions("1");
        consentRequest.getData().getInitiation().controlSum(new BigDecimal("10.00"));
        consentRequest.getData().getInitiation().localInstrument("Local-instrument");
        consentRequest.getData().getInitiation().supplementaryData(new OBSupplementaryData1());

        // When
        HttpResponse<OBWriteFileConsentResponse2> response = Unirest.post("https://rs-store:" + port + "/open-banking/v3.1/pisp/file-payment-consents/")
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, "x-jws-signature")
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json")
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body(consentRequest)
                .asObject(OBWriteFileConsentResponse2.class);

        // Then
        assertThat(response.getStatus()).isEqualTo(201);
        OBWriteFileConsentResponse2 consentResponse = response.getBody();
        FRFileConsent2 consent = repository.findById(consentResponse.getData().getConsentId()).get();
        assertThat(consent.getPispName()).isEqualTo(MockTppHelper.MOCK_PISP_NAME);
        assertThat(consent.getPispId()).isEqualTo(MockTppHelper.MOCK_PISP_ID);
        assertThat(consent.getId()).isEqualTo(consentResponse.getData().getConsentId());
        assertThat(consent.getInitiation()).isEqualTo(consentResponse.getData().getInitiation());
        assertThat(consent.getStatus().toOBExternalConsentStatus2Code()).isEqualTo(consentResponse.getData().getStatus());
        assertThat(consent.getObVersion()).isEqualTo(OBVersion.v3_1);
    }

    /**
     * Expected http 200 code
     * @throws UnirestException
     * @throws IOException
     */
    @Test
    public void testCreateFilePaymentConsentsFPSFile() throws UnirestException, IOException {
        // Given
        String fileConsentId = UUID.randomUUID().toString();
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        MockTppHelper.setupMockTpp(tppRepository);

        String csvFileContent = getContent(CSVFilePaymentConsentsRsStoreApiControllerTest.class.getClassLoader().getResource(RESOURCES_PACK + "/Batch-FPS-file.csv").getFile());

        FRFileConsent2 existingConsent = JMockData.mock(FRFileConsent2.class);
        existingConsent.setStatus(ConsentStatusCode.AWAITINGUPLOAD);
        existingConsent.setId(fileConsentId);
        existingConsent.setFileContent(null);
        existingConsent.setPayments(Collections.emptyList());
        existingConsent.setWriteFileConsent(new OBWriteFileConsent2().data(new OBWriteDataFileConsent2().initiation(new OBFile2()
                .fileHash("kdjfklsdjflksjf")
                .numberOfTransactions("3")
                .controlSum(new BigDecimal("0.6"))
                .fileType(CSVFilePaymentType.UK_LBG_FPS_BATCH_V10.getFileType())
        )));
        repository.save(existingConsent);

        // When
        HttpResponse response = Unirest.post("https://rs-store:" + port + "/open-banking/v3.1/pisp/file-payment-consents/" + fileConsentId + "/file")
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
                .header(ACCEPT, "application/json")
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body(csvFileContent)
                .asString();

        // Then
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(200);
        FRFileConsent2 consent = repository.findById(fileConsentId).get();
        assertThat(consent.getId()).isEqualTo(fileConsentId);
        assertThat(consent.getStatus().toOBExternalConsentStatus2Code()).isEqualTo(OBExternalConsentStatus2Code.AWAITINGAUTHORISATION);
        assertThat(consent.getFileContent()).isEqualTo(csvFileContent);
    }

    /**
     * Expected http 200 code
     * @throws UnirestException
     * @throws IOException
     */
    @Test
    public void testCreateFilePaymentConsentsBACSFile() throws UnirestException, IOException {
        // Given
        String fileConsentId = UUID.randomUUID().toString();
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        MockTppHelper.setupMockTpp(tppRepository);

        String csvFileContent = getContent(CSVFilePaymentConsentsRsStoreApiControllerTest.class.getClassLoader().getResource(RESOURCES_PACK + "/Bulk-BACS-file.csv").getFile());

        FRFileConsent2 existingConsent = JMockData.mock(FRFileConsent2.class);
        existingConsent.setStatus(ConsentStatusCode.AWAITINGUPLOAD);
        existingConsent.setId(fileConsentId);
        existingConsent.setFileContent(null);
        existingConsent.setPayments(Collections.emptyList());
        existingConsent.setWriteFileConsent(new OBWriteFileConsent2().data(new OBWriteDataFileConsent2().initiation(new OBFile2()
                .fileHash("kdjfklsdjflksjf")
                .numberOfTransactions("3")
                .controlSum(new BigDecimal("0.6"))
                .fileType(CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getFileType())
        )));
        repository.save(existingConsent);

        // When
        HttpResponse response = Unirest.post("https://rs-store:" + port + "/open-banking/v3.1/pisp/file-payment-consents/" + fileConsentId + "/file")
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
                .header(ACCEPT, "application/json")
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body(csvFileContent)
                .asString();

        // Then
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(200);
        FRFileConsent2 consent = repository.findById(fileConsentId).get();
        assertThat(consent.getId()).isEqualTo(fileConsentId);
        assertThat(consent.getStatus().toOBExternalConsentStatus2Code()).isEqualTo(OBExternalConsentStatus2Code.AWAITINGAUTHORISATION);
        assertThat(consent.getFileContent()).isEqualTo(csvFileContent);
    }

    /**
     * Expected http 400 error code<br/>
     * @throws UnirestException
     */
    @Test
    public void testCreateFilePaymentFileNotFound() throws UnirestException {
        // Given
        String fileConsentId = UUID.randomUUID().toString();
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        MockTppHelper.setupMockTpp(tppRepository);
        HttpResponse response = Unirest.post("https://rs-store:" + port + "/open-banking/v3.1/pisp/file-payment-consents/" + fileConsentId + "/file")
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
                .header(ACCEPT, "application/json")
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body("csvFileContent")
                .asJson();

        // then
        JsonNode jsonResponseBody = (JsonNode) response.getBody();
        JSONArray jsonErrors = (JSONArray) jsonResponseBody.getObject().get("Errors");
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(jsonResponseBody.getObject().get("Code")).isEqualTo("OBRI.Request.Invalid");
        assertThat(jsonErrors.optJSONObject(0).get("ErrorCode")).isEqualTo("OBRI.Payment.NotFound");
    }

    /**
     * Expected http 415 error code<br/>
     * @throws UnirestException
     */
    @Test
    public void testCreateFilePayment_Unsupported_MediaType() throws UnirestException {
        // Given
        String fileConsentId = UUID.randomUUID().toString();
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        MockTppHelper.setupMockTpp(tppRepository);
        HttpResponse response = Unirest.post("https://rs-store:" + port + "/open-banking/v3.1/pisp/file-payment-consents/" + fileConsentId + "/file")
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, "CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType()")
                .header(ACCEPT, "application/json")
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body("csvFileContent")
                .asJson();

        // then
        JsonNode jsonResponseBody = (JsonNode) response.getBody();
        JSONArray jsonErrors = (JSONArray) jsonResponseBody.getObject().get("Errors");
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(415);
        assertThat(jsonResponseBody.getObject().get("Code")).isEqualTo("OBRI.Request.Invalid");
        assertThat(jsonErrors.optJSONObject(0).get("ErrorCode")).isEqualTo("OBRI.Request.MediaType.NotSupported");
    }

    /**
     * Expected http 400 error code<br/>
     * @throws UnirestException
     */
    @Test
    public void testCreateFilePayment_Invalid_format() throws UnirestException {
        // Given
        String fileConsentId = UUID.randomUUID().toString();
        springSecForTest.mockAuthCollector.mockAuthorities(OBRIRole.ROLE_PISP);
        MockTppHelper.setupMockTpp(tppRepository);

        FRFileConsent2 existingConsent = JMockData.mock(FRFileConsent2.class);
        existingConsent.setStatus(ConsentStatusCode.AWAITINGUPLOAD);
        existingConsent.setId(fileConsentId);
        existingConsent.setFileContent(null);
        existingConsent.setPayments(Collections.emptyList());
        existingConsent.setWriteFileConsent(new OBWriteFileConsent2().data(new OBWriteDataFileConsent2().initiation(new OBFile2()
                .fileHash("kdjfklsdjflksjf")
                .numberOfTransactions("3")
                .controlSum(new BigDecimal("0.6"))
                .fileType(CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getFileType())
        )));
        repository.save(existingConsent);

        HttpResponse response = Unirest.post("https://rs-store:" + port + "/open-banking/v3.1/pisp/file-payment-consents/" + fileConsentId + "/file")
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
                .header(ACCEPT, "application/json")
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body("csvFileContent")
                .asJson();

        // then
        JsonNode jsonResponseBody = (JsonNode) response.getBody();
        JSONArray jsonErrors = (JSONArray) jsonResponseBody.getObject().get("Errors");
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(jsonResponseBody.getObject().get("Code")).isEqualTo("OBRI.Request.Invalid");
        assertThat(jsonErrors.optJSONObject(0).get("ErrorCode")).isEqualTo("UK.OBIE.Resource.InvalidFormat");
    }

    /**
     * Get the file content like a string
     * @param filePath
     * @return String file content
     * @throws IOException
     */
    @Ignore
    static final String getContent(String filePath) throws IOException {
        return Files.readString(Paths.get(filePath), StandardCharsets.UTF_8);
    }
}
