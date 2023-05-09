package com.pbear.gatewayauthserver.auth.oauth

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.server.*

@Configuration
class OAuthRouter {
    @Bean
    fun oauthRoute(oAuthHandler: OAuthHandler): RouterFunction<ServerResponse> = RouterFunctions
        .nest(
            RequestPredicates.path("/oauth"),
            router {
                POST("/token", oAuthHandler::handleOauthToken)
            }
        )
}