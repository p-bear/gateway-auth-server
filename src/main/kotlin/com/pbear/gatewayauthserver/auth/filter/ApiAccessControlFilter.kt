package com.pbear.gatewayauthserver.auth.filter

import mu.KotlinLogging
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class ApiAccessControlFilter: AbstractGatewayFilterFactory<ApiAccessControlFilter.Config>() {
    private val log = KotlinLogging.logger {  }

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->

        chain.filter(exchange).then(Mono.fromRunnable { log.info("qwer") })
    }



    class Config() {
    }
}
