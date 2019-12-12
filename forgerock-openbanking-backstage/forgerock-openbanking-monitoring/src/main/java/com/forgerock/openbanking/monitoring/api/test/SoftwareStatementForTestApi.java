/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.api.test;

import com.forgerock.openbanking.exceptions.OBErrorResponseException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiParam;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Api(tags = "Test-Software-Statement")
@RequestMapping(
        value = "/api/test/software-statement"
)
public interface SoftwareStatementForTestApi {

    @RequestMapping(
            value = "/{monitoringId}/certificate",
            method = RequestMethod.GET
    )
    ResponseEntity getDefaultCertificate(
            @ApiParam(value = "The monitoring ID.", required = true)
            @PathVariable String monitoringId

    ) throws OBErrorResponseException;

    @RequestMapping(
            value = "/",
            method = RequestMethod.POST
    )
    ResponseEntity createNewSoftwareStatement(
    ) throws OBErrorResponseException;


    @RequestMapping(
            value = "/{monitoringId}",
            method = RequestMethod.DELETE
    )
    ResponseEntity deleteSoftwareStatement(
            @ApiParam(value = "The monitoring ID.", required = true)
            @PathVariable String monitoringId
    ) throws OBErrorResponseException;

    @RequestMapping(
            value = "/",
            method = RequestMethod.DELETE
    )
    ResponseEntity deleteAllSoftwareStatement(
    ) throws OBErrorResponseException;
}
