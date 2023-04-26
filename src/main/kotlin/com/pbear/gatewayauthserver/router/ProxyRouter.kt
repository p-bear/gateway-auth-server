package com.pbear.gatewayauthserver.router

import mu.KotlinLogging
import org.springframework.cloud.gateway.route.RouteLocator
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ProxyRouter {
    private val log = KotlinLogging.logger {  }

    @Bean
    fun proxyRouterFunction(routeLocatorBuilder: RouteLocatorBuilder): RouteLocator = routeLocatorBuilder.routes()
        .route("all") { predicateSpec -> predicateSpec
            .predicate {
                var flag = true
                log.info("qwe")
                flag
            }
            .uri("http://192.168.0.103:40001")
        }
        .build()
}