/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.api.test;


import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.exceptions.OBErrorResponseException;
import com.forgerock.openbanking.model.SoftwareStatement;
import com.forgerock.openbanking.monitoring.ForgerockOpenbankingMonitoringApplication;
import com.forgerock.openbanking.monitoring.model.directory.Organisation;
import com.forgerock.openbanking.monitoring.model.directory.User;
import com.forgerock.openbanking.monitoring.services.directory.DirectoryService;
import com.forgerock.openbanking.monitoring.services.directory.UserService;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Controller
@Slf4j
public class SoftwareStatementForTestApiController implements SoftwareStatementForTestApi {
    private static final String FORGEROCK_LOGO_URI = "https://i.postimg.cc/hthQCJhR/fr-logo-square-1c-black.png";
    public static final String FORGE_ROCK = "ForgeRock";
    public static final String FORGE_ROCK_ORG_DESCRIPTION = "Organisation created for automated testing";
    @Autowired
    private DirectoryService directoryService;
    @Autowired
    private UserService userService;

    private static String SOFTWARE_STATEMENT_NAME_FOR_TEST = "ForTest";

    @Override
    @Cacheable(ForgerockOpenbankingMonitoringApplication.MONITORING_CERTIFICATE_CACHE)
    public ResponseEntity getDefaultCertificate(
            @ApiParam(value = "The monitoring ID.", required = true)
            @PathVariable String monitoringId
    )
            throws OBErrorResponseException {

        User user = userService.getUser();
        log.debug("Monitoring as user '{}'", user);
        SoftwareStatement softwareStatement = getSoftwareStatementForTest(user.getOrganisationId(), monitoringId);

        Application application = directoryService.getApplication(softwareStatement.getId());
        return ResponseEntity.ok(directoryService.getCurrentTransportPem(softwareStatement.getId(), application.getCurrentTransportKid()));
    }

    @Override
    public ResponseEntity createNewSoftwareStatement() throws OBErrorResponseException {
        // Get default user which will initialise/create the user
        User user = userService.getUser();

        String monitoringId = UUID.randomUUID().toString();
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(createSoftwareStatement(monitoringId, user.getOrganisationId()));
    }

    @Override
    public ResponseEntity deleteSoftwareStatement(
            @ApiParam(value = "The monitoring ID.", required = true)
            @PathVariable String monitoringId) throws OBErrorResponseException {
        return ResponseEntity.ok(directoryService.deleteSoftwareStatement(monitoringId));
    }

    @Override
    public ResponseEntity deleteAllSoftwareStatement() {
        User user = userService.getUser();
        log.debug("Monitoring as user '{}'", user);
        directoryService.deleteSoftwareStatements(user.getOrganisationId());
        return ResponseEntity.ok(true);
    }

    private SoftwareStatement getSoftwareStatementForTest(String organisationId, String monitoringId) {
        String softwareStatementName = SOFTWARE_STATEMENT_NAME_FOR_TEST + "_" + monitoringId;
        List<SoftwareStatement> softwareStatements = directoryService.getSoftwareStatements(organisationId);
        if (softwareStatements.isEmpty()) {
            return createSoftwareStatement(monitoringId, organisationId);
        }

        Optional<SoftwareStatement> isSoftwareStatement = softwareStatements.stream()
                .filter(s -> softwareStatementName.equals(s.getName()))
                .findAny();
        if (isSoftwareStatement.isPresent()) {
            return isSoftwareStatement.get();
        } else {
            return createSoftwareStatement(monitoringId, organisationId);
        }
    }

    private SoftwareStatement createSoftwareStatement(String monitoringId, String organisationId) {
        String softwareStatementName = SOFTWARE_STATEMENT_NAME_FOR_TEST + "_" + monitoringId;
        SoftwareStatement softwareStatement = new SoftwareStatement();
        softwareStatement.setId(monitoringId);
        softwareStatement.setName(softwareStatementName);
        softwareStatement.setLogoUri(FORGEROCK_LOGO_URI);

        Organisation organisation = directoryService.getOrganisation(organisationId);
        organisation.setName(FORGE_ROCK);
        organisation.setDescription(FORGE_ROCK_ORG_DESCRIPTION);
        directoryService.updateOrganisation(organisation);

        return directoryService.createSoftwareStatement(softwareStatement);
    }
}
