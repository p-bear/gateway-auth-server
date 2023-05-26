package com.pbear.gatewayauthserver.proxy.filter

import com.pbear.gatewayauthserver.auth.oauth.OAuthHandler
import com.pbear.gatewayauthserver.common.config.CustomUserDetail
import mu.KotlinLogging
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

@Component
class GoogleAccountApplyFilter(private val oAuthHandler: OAuthHandler): AbstractGatewayFilterFactory<GoogleAccountApplyFilter.Config>() {
    private val log = KotlinLogging.logger {  }

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        Mono.just(exchange.request.uri.path)
            .filter { it.contains("easyCalendar") }
            .flatMap { ReactiveSecurityContextHolder.getContext()
                .map { (it.authentication.credentials as CustomUserDetail).getAccessTokenRedis() }
                .flatMap(oAuthHandler::getGoogleToken)
                .flatMap {
                    chain.filter(exchange.mutate()
                        .request(exchange.request.mutate()
                            .header("googleAccessToken", it.accessToken).build())
                        .build())
                } }
            .switchIfEmpty { chain.filter(exchange) }
    }

    class Config() {
    }
}
