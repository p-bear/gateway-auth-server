package com.pbear.gatewayauthserver.proxy

import com.pbear.gatewayauthserver.auth.filter.ApiAccessControlFilter
import mu.KotlinLogging
import org.springframework.cloud.gateway.route.RouteLocator
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ProxyRouter(private val apiAccessControlFilter: ApiAccessControlFilter) {
    private val log = KotlinLogging.logger {  }

    @Bean
    fun proxyRouterFunction(routeLocatorBuilder: RouteLocatorBuilder): RouteLocator = routeLocatorBuilder.routes()
        .route("main") { predicateSpec ->
            predicateSpec
                .path("/main/**")
                .filters { it
                    .rewritePath("^/main", "")
                }
                .uri("http://192.168.0.103:40001")
        }
        .build()
}