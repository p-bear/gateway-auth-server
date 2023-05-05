package com.pbear.gatewayauthserver.auth.client.handler

import com.pbear.gatewayauthserver.auth.client.data.entity.ClientDetails
import com.pbear.gatewayauthserver.auth.client.repository.ClientDetailsRepository
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

@Service
class ClientHandler(
    private val clientDetailsRepository: ClientDetailsRepository,
    private val passwordEncoder: PasswordEncoder) {
    private val log = KotlinLogging.logger {  }

    @Value("\${client.secret.key}")
    val secretKey: String = ""

    fun postClient(serverRequest: ServerRequest): Mono<ServerResponse> {
        val secretKeyParam = serverRequest.queryParam("secretKey")
        if (secretKeyParam.isEmpty || secretKey != secretKeyParam.get()) {
            log.warn("fail to match secret key")
            return ServerResponse.status(HttpStatus.BAD_REQUEST).build()
        }

        return serverRequest.bodyToMono(ClientDetails::class.java)
            .doOnNext{ it.clientSecret = this.passwordEncoder.encode(it.clientSecret) }
            .flatMap {
                this.clientDetailsRepository.save(it)
            }
            .flatMap { ServerResponse.ok().build() }
    }

    fun deleteClient(serverRequest: ServerRequest): Mono<ServerResponse> {
        val secretKeyParam = serverRequest.queryParam("secretKey")
        if (secretKeyParam.isEmpty || secretKey != secretKeyParam.get()) {
            log.warn("fail to match secret key")
            return ServerResponse.status(HttpStatus.BAD_REQUEST).build()
        }

        return serverRequest
            .bodyToMono(HashMap::class.java)
            .flatMap {
                if (it["clientId"].toString().isNullOrEmpty()) {
                    ServerResponse.status(HttpStatus.BAD_REQUEST).build()
                } else {
                    this.clientDetailsRepository.deleteByClientIdAndClientAuthenticationMethod(
                        it["clientId"].toString(), it["clientAuthenticationMethod"].toString())
                }
            }
            .flatMap { ServerResponse.ok().build() }
    }
}