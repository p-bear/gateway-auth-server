package com.pbear.gatewayauthserver.auth.oauth.service

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.oauth2.sdk.token.Tokens
import com.pbear.gatewayauthserver.auth.client.repository.ClientDetailsRepository
import com.pbear.gatewayauthserver.auth.oauth.data.entity.AccessTokenRedis
import com.pbear.gatewayauthserver.auth.oauth.data.entity.RefreshTokenRedis
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import reactor.kotlin.core.publisher.switchIfEmpty
import java.time.Duration
import java.util.UUID

@Service
class TokenService(
    @Qualifier("AccessTokenReactiveRedisTemplate")
    private val accessTokenRedisTemplate: ReactiveRedisTemplate<String, AccessTokenRedis>,
    @Qualifier("refreshTokenReactiveRedisTemplate")
    private val refreshTokenRedisTemplate: ReactiveRedisTemplate<String, RefreshTokenRedis>,
    private val clientDetailsRepository: ClientDetailsRepository
) {
    companion object {
        const val ACCESS_TOKEN_PREFIX = "accessToken"
        const val REFRESH_TOKEN_PREFIX = "refreshToken"
    }

    fun getToken(tokenRequest: TokenRequest, clientAuthentication: ClientAuthentication): Mono<Tokens> {
        return when (tokenRequest.authorizationGrant.type) {
            GrantType.PASSWORD -> this.createAndSaveToken(clientAuthentication.clientID.value, clientAuthentication.method.value)
            GrantType.REFRESH_TOKEN -> Mono.just(Tokens(BearerAccessToken(), RefreshToken()))
            else -> throw ResponseStatusException(HttpStatus.BAD_REQUEST, "grantType not supported, grantType: ${tokenRequest.authorizationGrant.type.value}")
        }
    }

    fun createAndSaveToken(clientId: String, clientAuthenticationMethod: String): Mono<Tokens> {
        val accessTokenValue = UUID.randomUUID().toString()
        val refreshTokenValue = UUID.randomUUID().toString()

        return this.clientDetailsRepository
            .findByClientIdAndClientAuthenticationMethod(clientId, clientAuthenticationMethod)
            .switchIfEmpty { throw ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot find clientId: $clientId") }
            .zipWhen {
                this.accessTokenRedisTemplate.opsForValue()
                    .set(
                        "${ACCESS_TOKEN_PREFIX}_${accessTokenValue}",
                        AccessTokenRedis(
                            value = accessTokenValue,
                            clientId = it.clientId,
                            clientAuthenticationMethod = it.clientAuthenticationMethod,
                            scopes = it.scopes,
                            authorities = it.authorities,
                            grantType = it.grantTypes),
                        Duration.ofSeconds(it.accessTokenValidity))
            }
            .map {
                if (!it.t2) throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken")
                it.t1
            }
            .zipWhen {
                this.refreshTokenRedisTemplate.opsForValue()
                    .set("${REFRESH_TOKEN_PREFIX}_${refreshTokenValue}",
                        RefreshTokenRedis(refreshTokenValue, it.clientId, it.clientAuthenticationMethod),
                        Duration.ofSeconds(it.refreshTokenValidity))
            }
            .publishOn(Schedulers.boundedElastic())
            .map {
                if (!it.t2) {
                    this.accessTokenRedisTemplate.delete(accessTokenValue).toFuture().get()
                    throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken")
                }
                it.t1
            }
            .map {
                Tokens(
                    BearerAccessToken(
                        accessTokenValue,
                        it.accessTokenValidity,
                        Scope.parse(it.scopes)),
                    RefreshToken(refreshTokenValue))
            }
    }
}