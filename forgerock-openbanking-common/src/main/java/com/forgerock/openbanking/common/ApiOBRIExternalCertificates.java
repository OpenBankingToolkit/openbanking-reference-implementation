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
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.common.services.store.tpp.TppStoreService;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.model.Tpp;
import com.forgerock.spring.security.multiauth.model.granttypes.PSD2GrantType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.forgerock.openbanking.common.CertificateHelper.getCn;
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
        super(caCertificate, tppStoreService, obCA);
        this.caCertificate = caCertificate;
        this.tppStoreService = tppStoreService;
        this.obCA = obCA;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        if (roles != null) {
            authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
            authorities.add(OBRIRole.ROLE_TPP);
            authorities.add(OBRIRole.ROLE_EIDAS);
        }

        if (isCertificateIssuedByCA(caCertificate, certificatesChain)) {
            authorities.add(OBRIRole.ROLE_FORGEROCK_EXTERNAL_APP);
            authorities.add(OBRIRole.ROLE_TPP);
        }
        if (isCertificateIssuedByCA(obCA[0], certificatesChain)) { // checks obCA[0] rather than caCertificate in the common OBRIExternalCertificate class
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
    /**
     * Obtains the username from the certificate if that certificate is valid.
     * The OpenBanking APIs may be accessed using the following types of certificates;
     * - An OBWac certificate. This is effectively a test eIDAS cert issued and signed by Open Banking
     * - A ForgeRock Directory issued certificate. Issued by the ForgeRock Directory and signed by the
     *   obri-external-ca certificate.
     * - A valid eIDAS PSD2 certificate signed by a trusted CA found in a regularly updated system truststore.
     */
    public String getUserName(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo) {

        // additional check of obCA[0] compared to the common OBRIExternalCertificate class.
        if(!psd2CertInfo.isPsd2Cert()) {
            if (!isCertificateIssuedByCA(caCertificate, certificatesChain) && !isCertificateIssuedByCA(obCA[0], certificatesChain)) {
                log.warn("ApiOBRIExternalCertificates:getUserName(): Certificate is untrusted - returning null");
                return null;
            }
        }

        String cn = getCn(certificatesChain[0]);

        Optional<Tpp> optionalTpp = tppStoreService.findByCn(cn);
        if (!optionalTpp.isPresent()) {
            log.debug("TPP not found. This TPP {} is not on board yet", cn);
            return getCn(certificatesChain[0]);
        } else {
            return optionalTpp.get().getClientId();
        }
    }
}
