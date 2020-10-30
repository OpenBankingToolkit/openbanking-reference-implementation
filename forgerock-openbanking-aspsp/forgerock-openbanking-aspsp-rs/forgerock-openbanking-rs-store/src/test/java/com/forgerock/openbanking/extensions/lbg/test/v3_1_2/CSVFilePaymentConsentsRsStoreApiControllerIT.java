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
package com.forgerock.openbanking.extensions.lbg.test.v3_1_2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVFilePaymentFactory;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVFilePaymentType;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.model.CSVCreditIndicatorRow;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.model.CSVDebitIndicatorSection;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.model.CSVFilePayment;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.model.CSVHeaderIndicatorSection;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.validation.CSVValidation;
import com.forgerock.openbanking.aspsp.rs.store.ForgerockOpenbankingRsStoreApplication;
import com.forgerock.openbanking.aspsp.rs.store.repository.payments.FileConsentRepository;
import com.forgerock.openbanking.common.conf.RSConfiguration;
import com.forgerock.openbanking.common.model.openbanking.persistence.payment.ConsentStatusCode;
import com.forgerock.openbanking.common.model.openbanking.persistence.payment.FRFileConsent;
import com.forgerock.openbanking.common.model.version.OBVersion;
import com.forgerock.openbanking.exceptions.OBErrorException;
import com.forgerock.openbanking.extensions.lbg.test.MockTppHelper;
import com.forgerock.openbanking.integration.test.support.SpringSecForTest;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.repositories.TppRepository;
import com.github.jsonzou.jmockdata.JMockData;
import kong.unirest.HttpResponse;
import kong.unirest.JacksonObjectMapper;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
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
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import uk.org.openbanking.OBHeaders;
import uk.org.openbanking.datamodel.payment.OBExternalConsentStatus2Code;
import uk.org.openbanking.datamodel.payment.OBSupplementaryData1;
import uk.org.openbanking.datamodel.payment.OBWriteFileConsent3;
import uk.org.openbanking.datamodel.payment.OBWriteFileConsentResponse2;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static com.forgerock.openbanking.common.services.openbanking.converter.payment.FRWriteFileConsentConverter.toFRWriteFileConsent;
import static com.forgerock.openbanking.common.services.openbanking.converter.payment.FRWriteFileConsentConverter.toFRWriteFileDataInitiation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration(classes = ForgerockOpenbankingRsStoreApplication.class)
public class CSVFilePaymentConsentsRsStoreApiControllerIT {

    private static final String _URL = "/open-banking/v3.1.2/pisp/file-payment-consents/";
    private CSVFilePayment file;

    @LocalServerPort
    private int port;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private RSConfiguration rsConfiguration;
    @Autowired
    private FileConsentRepository repository;
    @MockBean
    private TppRepository tppRepository;

    @Autowired
    @Order(Ordered.HIGHEST_PRECEDENCE)
    private SpringSecForTest springSecForTest;

    @Before
    public void setUp() {
        Exception error = catchThrowableOfType(
                () -> setFile(),
                Exception.class
        );
        assertThat(error).isNull();
        assertThat(file).isNotNull();
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

        OBWriteFileConsent3 consentRequest = mockConsent(file.toString(), CSVFilePaymentType.UK_LBG_FPS_BATCH_V10.getFileType());

        // When
        HttpResponse<OBWriteFileConsentResponse2> response = Unirest.post("https://rs-store:" + port + _URL)
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
        FRFileConsent consent = repository.findById(consentResponse.getData().getConsentId()).get();
        assertThat(consent.getPispName()).isEqualTo(MockTppHelper.MOCK_PISP_NAME);
        assertThat(consent.getPispId()).isEqualTo(MockTppHelper.MOCK_PISP_ID);
        assertThat(consent.getId()).isEqualTo(consentResponse.getData().getConsentId());
        assertThat(consent.getInitiation()).isEqualTo(toFRWriteFileDataInitiation(consentResponse.getData().getInitiation()));
        assertThat(consent.getStatus().toOBExternalConsentStatus2Code()).isEqualTo(consentResponse.getData().getStatus());
        assertThat(consent.getObVersion()).isEqualTo(OBVersion.v3_1_2);
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

        OBWriteFileConsent3 consentRequest = mockConsent(file.toString(), CSVFilePaymentType.UK_LBG_FPS_BATCH_V10.getFileType());

        FRFileConsent existingConsent = mockFileConsent(fileConsentId, "", consentRequest);

        repository.save(existingConsent);

        // When
        HttpResponse response = Unirest.post("https://rs-store:" + port + _URL + fileConsentId + "/file")
                .accept(MediaType.APPLICATION_JSON_UTF8.toString())
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body(file.toString())
                .asString();

        // Then
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(200);
        FRFileConsent consent = repository.findById(fileConsentId).get();
        assertThat(consent.getId()).isEqualTo(fileConsentId);
        assertThat(consent.getStatus().toOBExternalConsentStatus2Code()).isEqualTo(OBExternalConsentStatus2Code.AWAITINGAUTHORISATION);
        assertThat(consent.getFileContent()).isEqualTo(file.toString());
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

        OBWriteFileConsent3 consentRequest = mockConsent(file.toString(), CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getFileType());

        FRFileConsent existingConsent = mockFileConsent(fileConsentId, "", consentRequest);

        repository.save(existingConsent);

        // When
        HttpResponse response = Unirest.post("https://rs-store:" + port + _URL + fileConsentId + "/file")
                .accept(MediaType.APPLICATION_JSON_UTF8.toString())
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
                .header("x-ob-client-id", MockTppHelper.MOCK_CLIENT_ID)
                .body(file.toString())
                .asString();

        // Then
        log.debug("{}. Response: {}", response.getStatus(), response.getBody() != null ? response.getBody() : response.getParsingError());
        assertThat(response.getStatus()).isEqualTo(200);
        FRFileConsent consent = repository.findById(fileConsentId).get();
        assertThat(consent.getId()).isEqualTo(fileConsentId);
        assertThat(consent.getStatus().toOBExternalConsentStatus2Code()).isEqualTo(OBExternalConsentStatus2Code.AWAITINGAUTHORISATION);
        assertThat(consent.getFileContent()).isEqualTo(file.toString());
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
        HttpResponse response = Unirest.post("https://rs-store:" + port + _URL + fileConsentId + "/file")
                .accept(MediaType.APPLICATION_JSON_UTF8.toString())
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
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
        HttpResponse response = Unirest.post("https://rs-store:" + port + _URL + fileConsentId + "/file")
                .accept(MediaType.APPLICATION_JSON_UTF8.toString())
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, "CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType()")
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

        OBWriteFileConsent3 consentRequest = mockConsent(file.toString(), CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getFileType());

        FRFileConsent existingConsent = mockFileConsent(fileConsentId, "", consentRequest);

        repository.save(existingConsent);

        HttpResponse response = Unirest.post("https://rs-store:" + port + _URL + fileConsentId + "/file")
                .accept(MediaType.APPLICATION_JSON_UTF8.toString())
                .header(OBHeaders.X_FAPI_FINANCIAL_ID, rsConfiguration.financialId)
                .header(OBHeaders.AUTHORIZATION, "token")
                .header(OBHeaders.X_IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                .header(OBHeaders.X_JWS_SIGNATURE, UUID.randomUUID().toString())
                .header(CONTENT_TYPE, CSVFilePaymentType.UK_LBG_BACS_BULK_V10.getContentType())
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
     * Create the consent request object
     * @param fileType
     * @return
     */
    @Ignore
    private static final OBWriteFileConsent3 mockConsent(String fileContent, String fileType){
        OBWriteFileConsent3 consentRequest = JMockData.mock(OBWriteFileConsent3.class);
        consentRequest.getData().getInitiation().fileHash(computeSHA256FullHash(fileContent));
        consentRequest.getData().getInitiation().fileReference("ref-001");
        consentRequest.getData().getInitiation().fileType(fileType);
        consentRequest.getData().getInitiation().numberOfTransactions("1");
        consentRequest.getData().getInitiation().controlSum(new BigDecimal("10.00"));
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
    @Ignore
    private static final FRFileConsent mockFileConsent(String fileConsentId, String csvFileContent, OBWriteFileConsent3 consentRequest){
        FRFileConsent frFileConsent2 = JMockData.mock(FRFileConsent.class);
        frFileConsent2.setStatus(ConsentStatusCode.AWAITINGAUTHORISATION);
        frFileConsent2.setId(fileConsentId);
        frFileConsent2.setFileContent(csvFileContent);
        frFileConsent2.setPayments(Collections.emptyList());
        frFileConsent2.setWriteFileConsent(toFRWriteFileConsent(consentRequest));
        return frFileConsent2;
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

    /**
     * Create a instance of CSVFilePayment
     * or reset the fields values to reuse it on every test
     *
     * @throws OBErrorException
     */
    @Ignore
    private void setFile() throws OBErrorException {
        if (file == null) {
            file = CSVFilePaymentFactory.create(CSVFilePaymentType.UK_LBG_FPS_BATCH_V10);
        }
        file.setHeaderIndicator(
                CSVHeaderIndicatorSection.builder()
                        .headerIndicator(CSVHeaderIndicatorSection.HEADER_IND_EXPECTED)
                        .fileCreationDate(file.getDateTimeFormatter().format(LocalDate.now()))
                        .uniqueId("ID001")
                        .numCredits(1)
                        .valueCreditsSum(new BigDecimal(10.10).setScale(2, RoundingMode.CEILING))
                        .build()
        );

        file.setDebitIndicator(
                CSVDebitIndicatorSection.builder()
                        .debitIndicator(CSVDebitIndicatorSection.DEBIT_IND_EXPECTED)
                        .paymentDate(file.getDateTimeFormatter().format(LocalDate.now().plusDays(2)))
                        .batchReference("Payments")
                        .debitAccountDetails("301775-12345678")
                        .build()
        );

        List row = new ArrayList<CSVCreditIndicatorRow>();
        row.add(
                CSVCreditIndicatorRow.builder()
                        .creditIndicator(CSVCreditIndicatorRow.CREDIT_IND_EXPECTED)
                        .recipientName("Beneficiary name")
                        .accNumber("12345678")
                        .recipientSortCode("301763")
                        .reference("Beneficiary ref.")
                        .debitAmount(new BigDecimal(10.10).setScale(2, RoundingMode.CEILING))
                        .paymentASAP(CSVValidation.PAYMENT_ASAP_VALUES[0])
                        .paymentDate("")
                        .eToEReference("EtoEReference")
                        .build()
        );

        file.setCreditIndicatorRows(row);
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
