/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

/**
 * This is required to support the large header sizes we use when signing payment file uploads
 */
@Component
public class WebServerConfig implements WebServerFactoryCustomizer<NettyReactiveWebServerFactory> {

    @Value("${server.max-http-header-size:165536}")
    private int maxHeaderSize;

    public void customize(NettyReactiveWebServerFactory container) {
        container.addServerCustomizers(
                httpServer -> httpServer.httpRequestDecoder(
                        httpRequestDecoderSpec -> httpRequestDecoderSpec.maxHeaderSize(maxHeaderSize)
                )
        );
    }

}
