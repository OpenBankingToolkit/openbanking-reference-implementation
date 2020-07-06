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
package com.forgerock.openbanking.monitoring.model.user;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UserRegistrationRequest {

    private Input input;

    @Data
    @Builder
    public static class Input {
        private User user;
    }

    @Data
    @Builder
    public static class User {
        private String username;
        private String userPassword;
        private List<String> sunIdentityMSISDNNumber;
    }

    /**
     * Authorities to access analytics @see <a href="https://github.com/OpenBankingToolkit/openbanking-toolkit/wiki/analytics" />
     */
    public enum AnalyticsAuthority {
        PUSH_KPI("PUSH_KPI"),

        READ_KPI("READ_KPI");

        private final String authority;

        AnalyticsAuthority(String authority) {
            this.authority = authority;
        }

        public String getAuthority() {
            return authority;
        }

        public static AnalyticsAuthority fromAuthority(String authority) {
            for(AnalyticsAuthority analyticsAuthority: AnalyticsAuthority.values()) {
                if (analyticsAuthority.authority.equals(authority)) {
                    return analyticsAuthority;
                }
            }
            throw new UnsupportedOperationException("Unsupported analytics authority: '" + authority + "'");
        }
    }
}
