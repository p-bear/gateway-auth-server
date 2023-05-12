package com.pbear.gatewayauthserver.auth.oauth

import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.RefreshTokenGrant
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.oauth2.sdk.token.Tokens
import com.pbear.gatewayauthserver.auth.client.ClientHandler
import com.pbear.gatewayauthserver.common.WebClientService
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty
import java.util.*

@Service
class TokenService(private val tokenStore: TokenStore,
                   private val clientHandler: ClientHandler,
                   private val webClientService: WebClientService) {

    fun getToken(tokenRequest: TokenRequest, clientAuthentication: ClientAuthentication): Mono<Tokens> {
        return when (tokenRequest.authorizationGrant.type) {
            GrantType.PASSWORD -> this.handlePasswordGrant(tokenRequest, clientAuthentication)
            GrantType.REFRESH_TOKEN -> this.handleRefreshTokenGrant(tokenRequest, clientAuthentication)
            GrantType.AUTHORIZATION_CODE -> this.handleAuthorizationCodeGrant(tokenRequest, clientAuthentication)
            else -> throw ResponseStatusException(HttpStatus.BAD_REQUEST, "grantType not supported, grantType: ${tokenRequest.authorizationGrant.type.value}")
        }
    }

    fun handlePasswordGrant(tokenRequest: TokenRequest, clientAuthentication: ClientAuthentication): Mono<Tokens> {
        val reqBodyGrant = tokenRequest.authorizationGrant as ResourceOwnerPasswordCredentialsGrant
        return this.webClientService.postCheckAccountPassword(reqBodyGrant.username, reqBodyGrant.password.value)
            .flatMap { accountPasswordResponse ->
                val accountId = (accountPasswordResponse["id"] as Int).toLong()
                this.tokenStore.getAccessToken(clientAuthentication.clientID.value, clientAuthentication.method.value, accountId)
                    // 기존 토큰이 없는 경우 AccessToken, RefreshToken 생성 및 저장
                    .switchIfEmpty { this.tokenStore.createSaveAccessTokenRefreshToken(clientAuthentication.clientID.value, clientAuthentication.method.value, accountId) }
            }
            .map { this.mapToTokens(it.value, it.issueTime, it.accessTokenValidity, it.scopes, it.refreshToken) }
    }

    fun handleRefreshTokenGrant(tokenRequest: TokenRequest, clientAuthentication: ClientAuthentication): Mono<Tokens> {
        val reqBodyGrant = tokenRequest.authorizationGrant as RefreshTokenGrant
        return this.refreshToken(
            clientAuthentication.clientID.value,
            clientAuthentication.method.value,
            reqBodyGrant.refreshToken.value)
    }

    fun handleAuthorizationCodeGrant(tokenRequest: TokenRequest, clientAuthentication: ClientAuthentication): Mono<Tokens> {
        val authorizationCodeGrant = tokenRequest.authorizationGrant as AuthorizationCodeGrant
        return this.tokenStore
            .getAccessTokenByAuthorizationCode(authorizationCodeGrant.authorizationCode.value)
            .map { this.mapToTokens(it.value, it.issueTime, it.accessTokenValidity, it.scopes, it.refreshToken) }
    }


    fun refreshToken(clientId: String, clientAuthenticationMethod: String, refreshTokenValue: String): Mono<Tokens> {
        return this.clientHandler.getClient(clientId, clientAuthenticationMethod)
            .switchIfEmpty { throw ResponseStatusException(HttpStatus.BAD_REQUEST, "fail to get ClientInfo") }
            .flatMap { clientDetails ->
                this.tokenStore.getRefreshToken(refreshTokenValue)
                    .switchIfEmpty { throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid refreshToken") }
                    .zipWhen { refreshTokenRedis ->
                        // accessToken이 있으면 delete
                        this.tokenStore.getAccessToken(refreshTokenRedis.accessToken)
                            .flatMap { accessTokenRedis ->
                                this.tokenStore.deleteAccessToken(accessTokenRedis)
                            }
                            .switchIfEmpty { Mono.just(true) }
                    }
                    .map { it.t1 }
                    .zipWhen { this.tokenStore.deleteRefreshToken(it) }
                    .map { it.t1 }
                    .flatMap { refreshTokenRedis ->
                        this.tokenStore.createSaveAccessTokenRefreshToken(
                            clientId,
                            clientAuthenticationMethod,
                            refreshTokenRedis.accountId)
                    }
                    .map { this.mapToTokens(it.value, it.issueTime, it.accessTokenValidity, it.scopes, it.refreshToken) }
            }
    }

    fun mapToTokens(accessTokenValue: String, issueTime: Long, accessTokenValidity: Long, scopes: String, refreshTokenValue: String): Tokens {
        return Tokens(
            BearerAccessToken(
                accessTokenValue,
                (issueTime + (accessTokenValidity * 1000) - Date().time) / 1000,
                Scope.parse(scopes)),
            RefreshToken(refreshTokenValue))
    }
}