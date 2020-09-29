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
package com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.api.v3_1_3;

import com.forgerock.openbanking.analytics.model.openbanking.OBReference;
import com.forgerock.openbanking.analytics.model.openbanking.OpenBankingAPI;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.exception.CSVErrorException;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVFilePaymentType;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.factory.CSVParserFactory;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.model.CSVFilePayment;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.parser.CSVParser;
import com.forgerock.openbanking.aspsp.rs.ext.lbg.file.payment.csv.validation.CSVValidationService;
import com.forgerock.openbanking.aspsp.rs.wrappper.RSEndpointWrapperService;
import com.forgerock.openbanking.common.model.openbanking.persistence.payment.FRFileConsent;
import com.forgerock.openbanking.common.services.store.RsStoreGateway;
import com.forgerock.openbanking.common.services.store.payment.FilePaymentService;
import com.forgerock.openbanking.exceptions.OBErrorException;
import com.forgerock.openbanking.exceptions.OBErrorResponseException;
import com.forgerock.openbanking.model.error.OBRIErrorResponseCategory;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.AuthorizationScope;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
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

import static com.forgerock.openbanking.constants.OpenBankingConstants.HTTP_DATE_FORMAT;

@Api(value = "csv-file-payment-consents", description = "the CSV file-payment-consents API")
@Controller("CSVFilePaymentConsentsApiV3.1.3")
@RequestMapping({"/open-banking/v3.1.3/pisp","/open-banking/v3.1.4/pisp","/open-banking/v3.1.5/pisp","/open-banking/v3.1.6/pisp"})
@Slf4j
public class CSVFilePaymentConsentsApiController {

    private final RSEndpointWrapperService rsEndpointWrapperService;
    private final RsStoreGateway rsStoreGateway;
    private final FilePaymentService filePaymentService;

    @Autowired
    public CSVFilePaymentConsentsApiController(RSEndpointWrapperService rsEndpointWrapperService, RsStoreGateway rsStoreGateway, FilePaymentService filePaymentService) {
        this.rsEndpointWrapperService = rsEndpointWrapperService;
        this.rsStoreGateway = rsStoreGateway;
        this.filePaymentService = filePaymentService;
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

            @ApiParam(value = "An Authorisation Token as per https://tools.ietf.org/html/rfc6750", required = true)
            @RequestHeader(value = "Authorization", required = true) String authorization,

            @ApiParam(value = "Every request will be processed only once per x-idempotency-key.  The Idempotency Key will be valid for 24 hours.", required = true)
            @RequestHeader(value = "x-idempotency-key", required = true) String xIdempotencyKey,

            @ApiParam(value = "A detached JWS signature of the body of the payload.", required = true)
            @RequestHeader(value = "x-jws-signature", required = true) String xJwsSignature,

            @ApiParam(value = "The time when the PSU last logged in with the TPP.  All dates in the HTTP headers are represented as RFC 7231 Full Dates. An example is below:  Sun, 10 Sep 2017 19:43:31 UTC")
            @RequestHeader(value = "x-fapi-auth-date", required = false)
            @DateTimeFormat(pattern = HTTP_DATE_FORMAT) DateTime xFapiAuthDate,

            @ApiParam(value = "The PSU's IP address if the PSU is currently logged in with the TPP.")
            @RequestHeader(value = "x-fapi-customer-ip-address", required = false) String xFapiCustomerIpAddress,

            @ApiParam(value = "An RFC4122 UID used as a correlation id.")
            @RequestHeader(value = "x-fapi-interaction-id", required = false) String xFapiInteractionId,

            @ApiParam(value = "Indicates the user-agent that the PSU is using.")
            @RequestHeader(value = "x-customer-user-agent", required = false) String xCustomerUserAgent,

            HttpServletRequest request,

            Principal principal
    ) throws OBErrorResponseException {
        log.trace("CVS controller.");
        log.trace("Received '{}'.", fileParam);
        FRFileConsent consent = filePaymentService.getPayment(consentId);
        try {
            CSVParser parser = CSVParserFactory.parse(CSVFilePaymentType.fromStringType(consent.getFileType().getFileType()), fileParam);
            CSVFilePayment filePayment = parser.parse().getCsvFilePayment();
            CSVValidationService.Consent.numTransactions(consent, filePayment);
            CSVValidationService.Consent.controlSum(consent, filePayment);
        } catch (OBErrorException | CSVErrorException e) {
            if (e instanceof CSVErrorException) {
                throw new OBErrorResponseException(((CSVErrorException) e).getCsvErrorType().getHttpStatus(), OBRIErrorResponseCategory.REQUEST_INVALID, "csv error", ((CSVErrorException) e).getOBError());
            } else {
                throw new OBErrorResponseException(((OBErrorException) e).getObriErrorType().getHttpStatus(), OBRIErrorResponseCategory.REQUEST_INVALID, "ob csv error", ((OBErrorException) e).getOBError());
            }
        }
        return rsEndpointWrapperService.filePaymentEndpoint()
                .authorization(authorization)
                .payment(consent)
                .xFapiFinancialId(rsEndpointWrapperService.rsConfiguration.financialId)
                .principal(principal)
                .filters(f -> {
                    f.verifyFileHash(fileParam);
                    f.verifyIdempotencyKeyLength(xIdempotencyKey);
                })
                .execute(
                        (String tppId) -> {
                            HttpHeaders additionalHttpHeaders = new HttpHeaders();
                            additionalHttpHeaders.add("x-ob-client-id", tppId);
                            ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};

                            return rsStoreGateway.toRsStore(request, additionalHttpHeaders, Collections.emptyMap(), String.class, fileParam);
                        }
                );
    }
}
