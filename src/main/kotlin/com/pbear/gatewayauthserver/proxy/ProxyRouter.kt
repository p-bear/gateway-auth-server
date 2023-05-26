package com.pbear.gatewayauthserver.proxy

import com.pbear.gatewayauthserver.proxy.filter.AccountApplyFilter
import com.pbear.gatewayauthserver.proxy.filter.GoogleAccountApplyFilter
import com.pbear.gatewayauthserver.proxy.filter.ApiAccessControlFilter
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.route.RouteLocator
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ProxyRouter(
    private val apiAccessControlFilter: ApiAccessControlFilter,
    private val accountApplyFilter: AccountApplyFilter,
    private val googleAccountApplyFilter: GoogleAccountApplyFilter
) {
    private val log = KotlinLogging.logger {  }

    @Value("\${route.main.url}")
    val mainRouteUrl: String = ""

    @Bean
    fun proxyRouterFunction(routeLocatorBuilder: RouteLocatorBuilder): RouteLocator = routeLocatorBuilder.routes()
        .route("main") { predicateSpec ->
            predicateSpec
                .path("/main/**")
                .filters { gatewayFilterSpec ->
                    gatewayFilterSpec
                        .filter(this.accountApplyFilter.apply(AccountApplyFilter.Config()))
                        .filter(this.googleAccountApplyFilter.apply(GoogleAccountApplyFilter.Config()))
                        .filter(this.apiAccessControlFilter.apply(ApiAccessControlFilter.Config()))
                        .rewritePath("^/main", "")
                }
                .uri(this.mainRouteUrl)
        }
        .build()
}