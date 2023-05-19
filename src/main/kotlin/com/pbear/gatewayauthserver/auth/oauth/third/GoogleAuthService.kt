package com.pbear.gatewayauthserver.auth.oauth.third

import com.pbear.gatewayauthserver.common.WebClientService
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class GoogleAuthService(private val webClientService: WebClientService) {
    @Value("\${google.main.clientId}")
    val mainClientId = ""
    @Value("\${google.main.clientSecret}")
    val mainClientSecret = ""
    @Value("\${google.main.redirectUri}")
    val mainRedirectUri = ""

    fun getMainGoogleAuthInfo(code: String): Mono<ResGooglePostOauthToken> {
        return this.webClientService.postGoogleOauth2V4Token(code, mainClientId, mainClientSecret, mainRedirectUri)
    }


}