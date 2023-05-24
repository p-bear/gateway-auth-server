package com.pbear.gatewayauthserver.auth.oauth

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.server.*

@Configuration
class OAuthRouter {
    @Bean
    fun oauthRoute(oAuthHandler: OAuthHandler): RouterFunction<ServerResponse> = RouterFunctions
        .nest(
            RequestPredicates.all(),
            router {
                POST("/oauth/token", oAuthHandler::handleOauthToken)
                GET("/authorize", oAuthHandler::handleGetAuthorize)
                POST("/oauth/token/google", oAuthHandler::handlePostOAuthTokenGoogle)
                GET("/oauth/token/google", oAuthHandler::handleGetOAuthTokenGoogle)
            }
        )
}