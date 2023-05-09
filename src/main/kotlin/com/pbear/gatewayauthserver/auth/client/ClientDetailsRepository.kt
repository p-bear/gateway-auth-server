package com.pbear.gatewayauthserver.auth.client

import org.springframework.data.repository.reactive.ReactiveCrudRepository
import reactor.core.publisher.Mono

interface ClientDetailsRepository: ReactiveCrudRepository<ClientDetails, Long> {
    fun findByClientIdAndClientAuthenticationMethod(clientId: String, clientAuthenticationMethod: String): Mono<ClientDetails>

    fun deleteByClientIdAndClientAuthenticationMethod(clientId: String, clientAuthenticationMethod: String): Mono<Void>
}