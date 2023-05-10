package com.pbear.gatewayauthserver.common

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono

@Service
class WebClientService(private val webClient: WebClient) {

    @Value("\${webclient.config.main.baseurl}")
    val mainServerBaseurl = ""

    fun postCheckAccountPassword(userId: String, password: String): Mono<HashMap<String, Any>> {
        return webClient.mutate()
            .baseUrl(mainServerBaseurl)
            .build()
            .post()
            .uri("/main/api/account/password")
            .bodyValue(mapOf("userId" to userId, "password" to password))
            .exchangeToMono {
                when (it.statusCode()) {
                    HttpStatus.OK -> it.bodyToMono(HashMap::class.java).map { res ->  res as HashMap<String, Any> }
                    else -> throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "fail to match id / password, id=$userId")
                }
            }
    }
}