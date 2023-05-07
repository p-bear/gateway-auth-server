package com.pbear.gatewayauthserver.auth.oauth.service

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant
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
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import reactor.kotlin.core.publisher.switchIfEmpty
import java.time.Duration
import java.util.Date
import java.util.UUID

@Service
class TokenService(
    private val reactiveRedisTemplate: ReactiveRedisTemplate<String, String>,
    @Qualifier("AccessTokenReactiveRedisTemplate")
    private val accessTokenRedisTemplate: ReactiveRedisTemplate<String, AccessTokenRedis>,
    @Qualifier("refreshTokenReactiveRedisTemplate")
    private val refreshTokenRedisTemplate: ReactiveRedisTemplate<String, RefreshTokenRedis>,
    private val clientDetailsRepository: ClientDetailsRepository,
    private val webClient: WebClient
) {
    companion object {
        private const val ACCESS_TOKEN_PREFIX = "accessToken"
        private const val CLIENT_ID_METHOD_ACCOUNT_ID_PREFIX = "clientIdMethodAccountId"
        private const val REFRESH_TOKEN_PREFIX = "refreshToken"

        fun getAccessTokenKey(accessTokenValue: String): String {
            return "${ACCESS_TOKEN_PREFIX}_${accessTokenValue}"
        }

        fun getClientIdMethodAccountIdKey(clientId: String, clientAuthenticationMethod: String, accountId: Long): String {
            return "${CLIENT_ID_METHOD_ACCOUNT_ID_PREFIX}_${clientId}_${clientAuthenticationMethod}_${accountId}"
        }

        fun getRefreshTokenKey(refreshTokenValue: String): String {
            return "${REFRESH_TOKEN_PREFIX}_${refreshTokenValue}"
        }
    }

    @Value("\${webclient.config.main.baseurl}")
    val mainServerBaseurl = ""

    fun getToken(tokenRequest: TokenRequest, clientAuthentication: ClientAuthentication): Mono<Tokens> {
        return when (tokenRequest.authorizationGrant.type) {
            GrantType.PASSWORD -> {
                val reqBodyGrant = tokenRequest.authorizationGrant as ResourceOwnerPasswordCredentialsGrant
                this.checkAccountPassword(reqBodyGrant.username, reqBodyGrant.password.value)
                    .zipWhen {
                        this.checkTokenExist(clientAuthentication.clientID.value, clientAuthentication.method.value, (it["id"] as Int).toLong())
                    }
                    .flatMap {
                        if (it.t2.isEmpty()) {
                            this.createAndSaveToken(
                                clientAuthentication.clientID.value,
                                clientAuthentication.method.value,
                                (it.t1["id"] as Int).toLong()
                            )
                        } else {
                            this.accessTokenRedisTemplate.opsForValue()
                                .get(getAccessTokenKey(it.t2))
                                .map { tokenDB ->
                                    Tokens(
                                        BearerAccessToken(
                                            tokenDB.value,
                                            (tokenDB.issueTime + (tokenDB.accessTokenValidity * 1000) - Date().time) / 1000,
                                            Scope.parse(tokenDB.scopes)),
                                        RefreshToken(tokenDB.refreshToken))
                                }
                        }
                    }
            }
            GrantType.REFRESH_TOKEN -> Mono.just(Tokens(BearerAccessToken(), RefreshToken()))
            else -> throw ResponseStatusException(HttpStatus.BAD_REQUEST, "grantType not supported, grantType: ${tokenRequest.authorizationGrant.type.value}")
        }
    }

    @SuppressWarnings("unchecked")
    fun checkAccountPassword(userId: String, password: String): Mono<HashMap<String, Any>> {
        return webClient.mutate()
            .baseUrl(mainServerBaseurl)
            .build()
            .post()
            .uri("/main/api/account/password")
            .bodyValue(mapOf("userId" to userId, "password" to password))
            .exchangeToMono {
                when (it.statusCode()) {
                    HttpStatus.OK -> it.bodyToMono(HashMap::class.java).map { res -> res as HashMap<String, Any> }
                    else -> throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "fail to match id / password, id=$password")
                }
            }
    }

    fun checkTokenExist(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<String> {
        return this.reactiveRedisTemplate.hasKey(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId))
            .flatMap {
                if (it) {
                    this.reactiveRedisTemplate
                        .opsForValue()
                        .get(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId))
                } else {
                    Mono.just("")
                }
            }
    }

    fun createAndSaveToken(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<Tokens> {
        val accessTokenValue = UUID.randomUUID().toString()
        val refreshTokenValue = UUID.randomUUID().toString()

        return this.clientDetailsRepository
            .findByClientIdAndClientAuthenticationMethod(clientId, clientAuthenticationMethod)
            .switchIfEmpty { throw ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot find clientId: $clientId") }
            .zipWhen {
                this.accessTokenRedisTemplate.opsForValue()
                    .set(
                        getAccessTokenKey(accessTokenValue),
                        AccessTokenRedis(
                            value = accessTokenValue,
                            clientId = it.clientId,
                            clientAuthenticationMethod = it.clientAuthenticationMethod,
                            accessTokenValidity = it.accessTokenValidity,
                            scopes = it.scopes,
                            authorities = it.authorities,
                            grantType = it.grantTypes,
                            accountId = accountId,
                            refreshToken = refreshTokenValue),
                        Duration.ofSeconds(it.accessTokenValidity))
            }
            .map {
                if (!it.t2) throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken")
                it.t1
            }
            .zipWhen {
                this.reactiveRedisTemplate.opsForValue()
                    .set(
                        getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId),
                        accessTokenValue,
                        Duration.ofSeconds(it.accessTokenValidity))
            }
            .publishOn(Schedulers.boundedElastic())
            .map {
                if (!it.t2) {
                    this.accessTokenRedisTemplate.delete(accessTokenValue).toFuture().get()
                    throw ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save clientIdAccountId")
                }
                it.t1
            }
            .zipWhen {
                this.refreshTokenRedisTemplate.opsForValue()
                    .set(getRefreshTokenKey(refreshTokenValue),
                        RefreshTokenRedis(refreshTokenValue, it.clientId, it.clientAuthenticationMethod, accountId),
                        Duration.ofSeconds(it.refreshTokenValidity))
            }
            .publishOn(Schedulers.boundedElastic())
            .map {
                if (!it.t2) {
                    this.accessTokenRedisTemplate.delete(accessTokenValue).toFuture().get()
                    this.reactiveRedisTemplate.delete(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId)).toFuture().get()
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

    fun checkAccessTokenExist(accessToken: String): Mono<AccessTokenRedis> {
        return this.accessTokenRedisTemplate.opsForValue()
            .get(getAccessTokenKey(accessToken))
    }
}