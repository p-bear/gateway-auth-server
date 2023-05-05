package com.pbear.gatewayauthserver.auth.client.router

import com.pbear.gatewayauthserver.auth.client.handler.ClientHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.server.*

@Configuration
class ClientRouter {
    @Bean
    fun clientRoute(clientHandler: ClientHandler): RouterFunction<ServerResponse> = RouterFunctions
        .nest(
            RequestPredicates.path("/oauth/client"),
            router {
                POST(clientHandler::postClient)
                DELETE(clientHandler::deleteClient)
            }
        )
}