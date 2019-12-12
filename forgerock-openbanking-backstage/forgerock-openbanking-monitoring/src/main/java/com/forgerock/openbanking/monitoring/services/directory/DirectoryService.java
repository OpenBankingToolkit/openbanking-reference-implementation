/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.services.directory;


import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.model.ApplicationIdentity;
import com.forgerock.openbanking.model.SoftwareStatement;
import com.forgerock.openbanking.monitoring.configuration.DirectoryConfiguration;
import com.forgerock.openbanking.monitoring.model.directory.Aspsp;
import com.forgerock.openbanking.monitoring.model.directory.Organisation;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

/**
 * Access the Jwk MS services
 */
@Service
@Slf4j
public class DirectoryService {

    private DirectoryConfiguration directoryConfiguration;
    private RestTemplate restTemplate;

    @Autowired
    public DirectoryService(DirectoryConfiguration directoryConfiguration, RestTemplate restTemplate) {
        this.directoryConfiguration = directoryConfiguration;
        this.restTemplate = restTemplate;
    }

    public ApplicationIdentity authenticate(JWK jwk) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<ApplicationIdentity> ptr = new ParameterizedTypeReference<ApplicationIdentity>() {};
        HttpEntity<String> request = new HttpEntity<>(jwk.toJSONObject().toJSONString(), headers);

        ResponseEntity<ApplicationIdentity> entity = restTemplate.exchange(directoryConfiguration.authenticateEndpoint,
                HttpMethod.POST, request, ptr);

        return entity.getBody();
    }

    public List<SoftwareStatement> getSoftwareStatements(String organisationId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<List<SoftwareStatement>> ptr = new ParameterizedTypeReference<List<SoftwareStatement>>() {};
        HttpEntity<String> request = new HttpEntity<>(headers);

       return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/organisation/" + organisationId + "/software-statements",
                HttpMethod.GET, request, ptr).getBody();
    }

    public void deleteSoftwareStatements(String organisationId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<List<SoftwareStatement>> ptr = new ParameterizedTypeReference<List<SoftwareStatement>>() {};
        HttpEntity<String> request = new HttpEntity<>(headers);

        restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/organisation/" + organisationId + "/software-statements",
                HttpMethod.DELETE, request, ptr).getBody();
    }

    public SoftwareStatement getCurrentSoftwareStatement() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<SoftwareStatement> ptr = new ParameterizedTypeReference<SoftwareStatement>() {};
        HttpEntity<String> request = new HttpEntity<>(headers);

        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/current",
                HttpMethod.GET, request, ptr).getBody();
    }

    public SoftwareStatement createSoftwareStatement(SoftwareStatement softwareStatement) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);


        ParameterizedTypeReference<SoftwareStatement> ptr = new ParameterizedTypeReference<SoftwareStatement>() {};
        HttpEntity<SoftwareStatement> request = new HttpEntity<>(softwareStatement, headers);

        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/",
                HttpMethod.POST, request, ptr).getBody();
    }

    public SoftwareStatement updateSoftwareStatement(SoftwareStatement softwareStatement) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);


        ParameterizedTypeReference<SoftwareStatement> ptr = new ParameterizedTypeReference<SoftwareStatement>() {};
        HttpEntity<SoftwareStatement> request = new HttpEntity<>(softwareStatement, headers);

        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/" + softwareStatement.getId(),
                HttpMethod.PUT, request, ptr).getBody();
    }

    public String generateSSA(SoftwareStatement softwareStatement) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        HttpEntity request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/"
                        + softwareStatement.getId() + "/ssa",
                HttpMethod.POST, request, ptr).getBody();
    }

    public boolean deleteSoftwareStatement(String softwareStatementId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);


        ParameterizedTypeReference<SoftwareStatement> ptr = new ParameterizedTypeReference<SoftwareStatement>() {};
        HttpEntity<SoftwareStatement> request = new HttpEntity<>(headers);

        restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/" + softwareStatementId,
                HttpMethod.DELETE, request, ptr);
        return true;
    }

    public String getCurrentTransportPem(String softwareStatementId, String kid) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        HttpEntity<String> request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/" + softwareStatementId
                        + "/application/" + kid + "/download/publicCert",
                HttpMethod.GET, request, ptr).getBody();
    }

    public Application getApplication(String softwareStatementId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<Application> ptr = new ParameterizedTypeReference<Application>() {};
        HttpEntity request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/software-statement/" + softwareStatementId
                        + "/application",
                HttpMethod.GET, request, ptr).getBody();
    }

    public String login(String idToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Id-Token", idToken);

        ParameterizedTypeReference<String> ptr = new ParameterizedTypeReference<String>() {};
        HttpEntity request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/user/login",
                HttpMethod.GET, request, ptr).getBody();
    }

    public List<Aspsp> getAPSPSPs() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<List<Aspsp>> ptr = new ParameterizedTypeReference<List<Aspsp>>() {};
        HttpEntity request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/aspsp/",
                HttpMethod.GET, request, ptr).getBody();
    }

    public Organisation getOrganisation(String organisationId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<Organisation> ptr = new ParameterizedTypeReference<Organisation>() {};
        HttpEntity request = new HttpEntity<>(headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/organisation/" + organisationId,
                HttpMethod.GET, request, ptr).getBody();
    }

    public Organisation updateOrganisation(Organisation organisation) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ParameterizedTypeReference<Organisation> ptr = new ParameterizedTypeReference<Organisation>() {};
        HttpEntity<Organisation> request = new HttpEntity<>(organisation, headers);
        return restTemplate.exchange(directoryConfiguration.rootEndpoint + "/api/organisation/" + organisation.getId(),
                HttpMethod.PUT, request, ptr).getBody();
    }
}
