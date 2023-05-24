package com.pbear.gatewayauthserver.proxy.filter

import mu.KotlinLogging
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class ApiAccessControlFilter: AbstractGatewayFilterFactory<ApiAccessControlFilter.Config>() {
    private val log = KotlinLogging.logger {  }

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        // TODO: req url 로깅 및 header에 accountId 처리?
        chain.filter(exchange).then(Mono.fromRunnable { log.info("test-log") })
    }



    class Config() {
    }
}
