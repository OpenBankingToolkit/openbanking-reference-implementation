/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.monitoring.model.user;

import lombok.Builder;
import lombok.Data;

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
    }
}
