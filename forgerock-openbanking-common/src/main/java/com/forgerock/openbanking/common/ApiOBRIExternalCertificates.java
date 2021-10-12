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
package com.forgerock.openbanking.common;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.psd2.Psd2Role;
import com.forgerock.cert.psd2.RoleOfPsp;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.spring.security.multiauth.model.granttypes.PSD2GrantType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.forgerock.openbanking.common.CertificateHelper.isCertificateIssuedByCA;

/**
 * A specific variation of {@link OBRIExternalCertificates} for the as-api and rs-api applications.
 */
@Slf4j
public class ApiOBRIExternalCertificates extends OBRIExternalCertificates {

    private final X509Certificate caCertificate;
    private final TppStoreService tppStoreService;
    private final X509Certificate[] obCA;

    public ApiOBRIExternalCertificates(X509Certificate caCertificate, TppStoreService tppStoreService, X509Certificate[] obCA) {
        super(caCertificate, obCA);
        this.caCertificate = caCertificate;
        this.tppStoreService = tppStoreService;
        this.obCA = obCA;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo,
                                                RolesOfPsp roles) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        if(psd2CertInfo != null && psd2CertInfo.isPsd2Cert()){
            authorities.add(OBRIRole.ROLE_EIDAS);

            if (isCertificateIssuedByCA(caCertificate, certificatesChain)) {
                authorities.add(OBRIRole.ROLE_FORGEROCK_EXTERNAL_APP);
                authorities.add(OBRIRole.ROLE_TPP);
            }

            if (isCertificateIssuedByCA(obCA[0], certificatesChain)) { // checks obCA[0] rather than caCertificate in the common OBRIExternalCertificate class
                authorities.add(OBRIRole.ROLE_TPP);
            }

            authorities.add(OBRIRole.ROLE_TPP);
            if (roles != null) {
                for(RoleOfPsp role:  roles.getRolesOfPsp()){
                    Psd2Role psd2Role = role.getRole();
                    OBRIRole.getRoleFromPsd2Role(psd2Role).ifPresent(r->authorities.add(r));
                }
                authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
            }
        } else {
            authorities.add(OBRIRole.UNKNOWN_CERTIFICATE);
        }
        return authorities;
    }

    @Override
    /**
     * Obtains the username from the certificate if that certificate is valid.
     * The OpenBanking APIs may be accessed using the following types of certificates;
     * - An OBWac certificate. This is effectively a test eIDAS cert issued and signed by Open Banking
     * - A ForgeRock Directory issued certificate. Issued by the ForgeRock Directory and signed by the
     *   obri-external-ca certificate.
     * - A valid eIDAS PSD2 certificate signed by a trusted CA found in a regularly updated system truststore.
     */
    public String getUserName(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo) throws InvalidEidasCertType{
        log.debug("getUserName() called on ApiOBRIExternalCertificates");
        // additional check of obCA[0] compared to the common OBRIExternalCertificate class.
        if(!psd2CertInfo.isPsd2Cert()) {
            if (!isCertificateIssuedByCA(caCertificate, certificatesChain) && !isCertificateIssuedByCA(obCA[0], certificatesChain)) {
                log.warn("ApiOBRIExternalCertificates:getUserName(): Certificate is untrusted - returning null");
                return null;
            }
            log.warn("The presented certificate is not a PSD eIDAS certificate. Returning null username");
            return null;
        }
        String organizationId = psd2CertInfo.getOrganizationId().orElse(null);
        log.info("getUserName() returning AuthorizationNumber from certificate '{}'", organizationId);
        return  organizationId;
    }
}
