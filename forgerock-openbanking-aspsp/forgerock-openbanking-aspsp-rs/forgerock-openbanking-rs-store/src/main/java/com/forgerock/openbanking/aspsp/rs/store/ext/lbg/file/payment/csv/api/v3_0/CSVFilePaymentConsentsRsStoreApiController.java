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
package com.forgerock.openbanking.aspsp.rs.store.ext.lbg.file.payment.csv.api.v3_0;

import com.forgerock.openbanking.analytics.model.openbanking.OBReference;
import com.forgerock.openbanking.analytics.model.openbanking.OpenBankingAPI;
import com.forgerock.openbanking.analytics.services.ConsentMetricService;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.exception.CSVErrorException;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVFilePaymentType;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVParserFactory;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVValidationFactory;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.model.CSVFilePayment;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.parser.CSVParser;
import com.forgerock.openbanking.repositories.TppRepository;
import com.forgerock.openbanking.aspsp.rs.store.repository.v3_1_5.payments.FileConsent5Repository;
import com.forgerock.openbanking.common.conf.discovery.ResourceLinkService;
import com.forgerock.openbanking.common.model.openbanking.forgerock.ConsentStatusCode;
import com.forgerock.openbanking.common.model.openbanking.v3_1_5.payment.FRFileConsent5;
import com.forgerock.openbanking.exceptions.OBErrorException;
import com.forgerock.openbanking.exceptions.OBErrorResponseException;
import com.forgerock.openbanking.model.error.OBRIErrorResponseCategory;
import com.forgerock.openbanking.model.error.OBRIErrorType;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.AuthorizationScope;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import uk.org.openbanking.datamodel.error.OBErrorResponse1;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.security.Principal;
import java.util.Collections;
import java.util.Date;

import static com.forgerock.openbanking.common.services.openbanking.IdempotencyService.validateIdempotencyRequest;
import static com.forgerock.openbanking.constants.OpenBankingConstants.HTTP_DATE_FORMAT;

@Api(value = "csv-file-payment-consents", description = "the CSV file-payment-consents API")
@Controller("CSVFilePaymentConsentsApiV3.0")
@RequestMapping({"/open-banking/v3.0/pisp","/open-banking/v3.1/pisp","/open-banking/v3.1.1/pisp","/open-banking/v3.1.2/pisp"})
@Slf4j
public class CSVFilePaymentConsentsRsStoreApiController {

    private final TppRepository tppRepository;
    private final FileConsent5Repository fileConsentRepository;
    private final ResourceLinkService resourceLinkService;
    private ConsentMetricService consentMetricService;

    public CSVFilePaymentConsentsRsStoreApiController(
            @Qualifier("webClientConsentMetricService") ConsentMetricService consentMetricService,
            TppRepository tppRepository,
            FileConsent5Repository fileConsentRepository,
            ResourceLinkService resourceLinkService
    ) {
        this.tppRepository = tppRepository;
        this.fileConsentRepository = fileConsentRepository;
        this.resourceLinkService = resourceLinkService;
        this.consentMetricService = consentMetricService;
    }

    @ApiOperation(value = "Create CSV File Payment Consents", nickname = "csvCreateFilePaymentConsentsConsentIdFile", notes = "", authorizations = {
            @Authorization(value = "TPPOAuth2Security", scopes = {
                    @AuthorizationScope(scope = "payments", description = "Generic payment scope")
            })
    }, tags = {"File Payments",})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "File Payment Consents Created"),
            @ApiResponse(code = 400, message = "Bad request", response = OBErrorResponse1.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not found"),
            @ApiResponse(code = 405, message = "Method Not Allowed"),
            @ApiResponse(code = 406, message = "Not Acceptable"),
            @ApiResponse(code = 415, message = "Unsupported Media Type"),
            @ApiResponse(code = 429, message = "Too Many Requests"),
            @ApiResponse(code = 500, message = "Internal Server Error", response = OBErrorResponse1.class)})
    @PreAuthorize("hasAuthority('ROLE_PISP')")
    @OpenBankingAPI(
            obReference = OBReference.CREATE_FILE_PAYMENT_FILE
    )
    @RequestMapping(value = "/file-payment-consents/{ConsentId}/file",
            produces = {"application/json; charset=utf-8"},
            consumes = {"text/plain; charset=utf-8"},
            method = RequestMethod.POST)
    ResponseEntity<Void> csvCreateFilePaymentConsentsConsentIdFile(
            @ApiParam(value = "Default", required = true)
            @Valid
            @RequestBody String fileParam,

            @ApiParam(value = "ConsentId", required = true)
            @PathVariable("ConsentId") String consentId,

            @ApiParam(value = "The unique id of the ASPSP to which the request is issued. The unique id will be issued by OB.", required = true)
            @RequestHeader(value = "x-fapi-financial-id", required = true) String xFapiFinancialId,

            @ApiParam(value = "An Authorisation Token as per https://tools.ietf.org/html/rfc6750", required = true)
            @RequestHeader(value = "Authorization", required = true) String authorization,

            @ApiParam(value = "Every request will be processed only once per x-idempotency-key.  The Idempotency Key will be valid for 24 hours.", required = true)
            @RequestHeader(value = "x-idempotency-key", required = true) String xIdempotencyKey,

            @ApiParam(value = "A detached JWS signature of the body of the payload.", required = true)
            @RequestHeader(value = "x-jws-signature", required = true) String xJwsSignature,

            @ApiParam(value = "The time when the PSU last logged in with the TPP.  All dates in the HTTP headers are represented as RFC 7231 Full Dates. An example is below:  Sun, 10 Sep 2017 19:43:31 UTC")
            @RequestHeader(value = "x-fapi-customer-last-logged-time", required = false)
            @DateTimeFormat(pattern = HTTP_DATE_FORMAT) DateTime xFapiCustomerLastLoggedTime,

            @ApiParam(value = "The PSU's IP address if the PSU is currently logged in with the TPP.")
            @RequestHeader(value = "x-fapi-customer-ip-address", required = false) String xFapiCustomerIpAddress,

            @ApiParam(value = "An RFC4122 UID used as a correlation id.")
            @RequestHeader(value = "x-fapi-interaction-id", required = false) String xFapiInteractionId,

            @ApiParam(value = "Indicates the user-agent that the PSU is using.")
            @RequestHeader(value = "x-customer-user-agent", required = false) String xCustomerUserAgent,

            HttpServletRequest request,

            Principal principal
    ) throws OBErrorResponseException {
        log.trace("CVS store controller.");
        log.trace("Received '{}'.", fileParam);

        final FRFileConsent5 fileConsent = fileConsentRepository.findById(consentId)
                .orElseThrow(() -> new OBErrorResponseException(
                        HttpStatus.BAD_REQUEST,
                        OBRIErrorResponseCategory.REQUEST_INVALID,
                        OBRIErrorType.PAYMENT_ID_NOT_FOUND
                                .toOBError1(consentId)
                ));

        // If file already exists it could be idempotent request
        if (!StringUtils.isEmpty(fileConsent.getFileContent())) {
            if (xIdempotencyKey.equals(fileConsent.getIdempotencyKey())) {
                validateIdempotencyRequest(xIdempotencyKey, fileConsent);
                log.info("File already exists for consent: '{}' and has matching idempotent key: '{}'. No action taken but returning 200/OK", fileConsent.id, fileConsent.idempotencyKey);
                return ResponseEntity.ok().build();
            } else {
                log.debug("This consent already has a file uploaded and the idempotency key does not match the previous upload so rejecting.");
                throw new OBErrorResponseException(
                        HttpStatus.FORBIDDEN,
                        OBRIErrorResponseCategory.REQUEST_INVALID, "cvs store error",
                        OBRIErrorType.PAYMENT_ALREADY_SUBMITTED
                                .toOBError1(fileConsent.getStatus().toOBExternalConsentStatus2Code())
                );
            }
        }

        // We parse the file and check metadata against the parsed file
        try {
            CSVParser parser = CSVParserFactory.parse(CSVFilePaymentType.fromStringType(fileConsent.getFileType().getFileType()), fileParam);
            CSVFilePayment paymentFile = parser.parse().getCsvFilePayment();
            CSVValidationFactory.getValidationServiceInstance(paymentFile).validate();

            //PaymentFile paymentFile = PaymentFileFactory.createPaymentFile(fileConsent.getFileType(), fileParam);
            log.info("Successfully parsed file of type: '{}' for consent: '{}'", fileConsent.getFileType(), fileConsent.getId());

            fileConsent.setPayments(Collections.EMPTY_LIST);
            fileConsent.setFileContent(fileParam);
            fileConsent.setUpdated(new Date());
            fileConsent.setStatus(ConsentStatusCode.AWAITINGAUTHORISATION);
            fileConsent.setStatusUpdate(DateTime.now());
            fileConsentRepository.save(fileConsent);
        } catch (OBErrorException | CSVErrorException e) {
            if (e instanceof CSVErrorException) {
                throw new OBErrorResponseException(((CSVErrorException) e).getCsvErrorType().getHttpStatus(), OBRIErrorResponseCategory.REQUEST_INVALID, "csv store error", ((CSVErrorException) e).getOBError());
            } else {
                throw new OBErrorResponseException(((OBErrorException) e).getObriErrorType().getHttpStatus(), OBRIErrorResponseCategory.REQUEST_INVALID, "ob csv store error", ((OBErrorException) e).getOBError());
            }
        }

        return ResponseEntity.ok().build();
    }
}
