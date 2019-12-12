/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

@Service
@ConfigurationProperties(prefix = "as.headless")
public class HeadLessAuthProperties {
    public static class DefaultPsu {
        private String username;
        private String password;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    private boolean alwaysEnable;
    private boolean headerEnable;
    private DefaultPsu defaultPsu;

    public boolean isAlwaysEnable() {
        return alwaysEnable;
    }

    public void setAlwaysEnable(boolean alwaysEnable) {
        this.alwaysEnable = alwaysEnable;
    }

    public boolean isHeaderEnable() {
        return headerEnable;
    }

    public void setHeaderEnable(boolean headerEnable) {
        this.headerEnable = headerEnable;
    }

    public DefaultPsu getDefaultPsu() {
        return defaultPsu;
    }

    public void setDefaultPsu(DefaultPsu defaultPsu) {
        this.defaultPsu = defaultPsu;
    }
}