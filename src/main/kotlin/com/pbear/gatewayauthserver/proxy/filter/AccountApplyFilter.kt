package com.pbear.gatewayauthserver.proxy.filter

import com.pbear.gatewayauthserver.common.config.CustomUserDetail
import mu.KotlinLogging
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import reactor.kotlin.core.publisher.switchIfEmpty

@Component
class AccountApplyFilter: AbstractGatewayFilterFactory<AccountApplyFilter.Config>() {
    private val log = KotlinLogging.logger {  }

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        ReactiveSecurityContextHolder.getContext()
            .map { (it.authentication.credentials as CustomUserDetail).getAccessTokenRedis() }
            .flatMap {
                chain.filter(exchange.mutate()
                    .request(exchange.request.mutate().header("accountId", it.accountId.toString()).build())
                    .build())
            }
            .switchIfEmpty { chain.filter(exchange) }
    }

    class Config() {
    }
}
