package com.pbear.gatewayauthserver.common

import com.nimbusds.oauth2.sdk.GrantType
import com.pbear.gatewayauthserver.auth.oauth.third.ReqMainPostAccountGoogle
import com.pbear.gatewayauthserver.auth.oauth.third.ResGooglePostOauthToken
import com.pbear.gatewayauthserver.auth.oauth.third.ResMainGetAccountGoogle
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

@Service
class WebClientService(private val webClient: WebClient) {

    @Value("\${webclient.config.main.baseurl}")
    val mainServerBaseurl = ""

    @Value("\${google.api.url}")
    val googleApiServerBaseurl = ""

    fun postCheckAccountPassword(userId: String, password: String): Mono<HashMap<String, Any>> {
        return this.webClient.mutate()
            .baseUrl(this.mainServerBaseurl)
            .build()
            .post()
            .uri("/api/account/password")
            .bodyValue(mapOf("userId" to userId, "password" to password))
            .exchangeToMono {
                when (it.statusCode()) {
                    HttpStatus.OK -> it.bodyToMono(HashMap::class.java).map { res ->  res as HashMap<String, Any> }
                    else -> throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "fail to match id / password, id=$userId")
                }
            }
    }

    fun getAccountGoogle(accountId: Long): Mono<ResMainGetAccountGoogle> {
        return this.webClient.mutate()
            .baseUrl(this.mainServerBaseurl)
            .build()
            .get()
            .uri(UriComponentsBuilder.fromUriString(this.mainServerBaseurl)
                .path("/api/account/google")
                .queryParam("accountId", accountId)
                .build()
                .toUri())
            .retrieve()
            .bodyToMono(ResMainGetAccountGoogle::class.java)
    }

    fun postAccountGoogle(reqMainPostAccountGoogle: ReqMainPostAccountGoogle): Mono<ResMainGetAccountGoogle> {
        return this.webClient.mutate()
            .baseUrl(this.mainServerBaseurl)
            .build()
            .post()
            .uri("/api/account/google")
            .bodyValue(reqMainPostAccountGoogle)
            .retrieve()
            .bodyToMono(ResMainGetAccountGoogle::class.java)
    }

    fun postGoogleOauth2V4Token(code: String, googleClientId: String, googleClientSecret: String, redirectUri: String): Mono<ResGooglePostOauthToken> {
        return this.webClient.mutate()
            .baseUrl(this.googleApiServerBaseurl)
            .build()
            .post()
            .uri("/oauth2/v4/token")
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .body(BodyInserters
                .fromFormData("code", code)
                .with("client_id", googleClientId)
                .with("client_secret", googleClientSecret)
                .with("redirect_uri", redirectUri)
                .with("grant_type", GrantType.AUTHORIZATION_CODE.value))
            .retrieve()
            .bodyToMono(ResGooglePostOauthToken::class.java)
    }
}