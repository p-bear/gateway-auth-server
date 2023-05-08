package com.pbear.gatewayauthserver.auth.oauth.service

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.RefreshTokenGrant
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.oauth2.sdk.token.Tokens
import com.pbear.gatewayauthserver.auth.client.data.entity.ClientDetails
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
                            this.createAndSaveToken(clientAuthentication.clientID.value, clientAuthentication.method.value, (it.t1["id"] as Int).toLong())
                        } else {
                            getAccessToken(it.t2)
                        }
                    }
            }
            GrantType.REFRESH_TOKEN -> {
                val reqBodyGrant = tokenRequest.authorizationGrant as RefreshTokenGrant
                this.refreshToken(
                    clientAuthentication.clientID.value,
                    clientAuthentication.method.value,
                    reqBodyGrant.refreshToken.value)
            }
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
            .flatMap { this.saveAccessToken(it, accessTokenValue, accountId, refreshTokenValue) }
            .flatMap { this.saveAccountTokenMapping(it, accessTokenValue, accountId) }
            .flatMap { this.saveRefreshToken(it, accessTokenValue, refreshTokenValue, accountId) }
            .map {
                Tokens(
                    BearerAccessToken(
                        accessTokenValue,
                        it.accessTokenValidity,
                        Scope.parse(it.scopes)),
                    RefreshToken(refreshTokenValue))
            }
    }

    fun getAccessToken(accessTokenValue: String): Mono<Tokens> {
        return this.accessTokenRedisTemplate.opsForValue()
            .get(getAccessTokenKey(accessTokenValue))
            .map { tokenDB ->
                Tokens(
                    BearerAccessToken(
                        tokenDB.value,
                        (tokenDB.issueTime + (tokenDB.accessTokenValidity * 1000) - Date().time) / 1000,
                        Scope.parse(tokenDB.scopes)),
                    RefreshToken(tokenDB.refreshToken))
            }
    }

    fun saveAccessToken(clientDetails: ClientDetails, accessTokenValue: String, accountId: Long, refreshTokenValue: String): Mono<ClientDetails> {
        return this.accessTokenRedisTemplate.opsForValue()
            .set(
                getAccessTokenKey(accessTokenValue),
                AccessTokenRedis(accessTokenValue, clientDetails, accountId, refreshTokenValue),
                Duration.ofSeconds(clientDetails.accessTokenValidity))
            .handle { it, sink ->
                if (!it) {
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken"))
                    return@handle
                }
                sink.next(clientDetails)
            }
    }

    fun saveAccountTokenMapping(clientDetails: ClientDetails, accessTokenValue: String, accountId: Long): Mono<ClientDetails> {
        return this.reactiveRedisTemplate.opsForValue()
            .set(
                getClientIdMethodAccountIdKey(clientDetails.clientId, clientDetails.clientAuthenticationMethod, accountId),
                accessTokenValue,
                Duration.ofSeconds(clientDetails.accessTokenValidity))
            .publishOn(Schedulers.boundedElastic())
            .handle { it, sink ->
                if (!it) {
                    this.accessTokenRedisTemplate.delete(accessTokenValue).toFuture().get()
                    sink.error(
                        ResponseStatusException(
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "fail to save clientIdAccountId"
                        )
                    )
                    return@handle
                }
                sink.next(clientDetails)
            }
    }

    fun saveRefreshToken(clientDetails: ClientDetails, accessTokenValue: String, refreshTokenValue: String, accountId: Long): Mono<ClientDetails> {
        return this.refreshTokenRedisTemplate.opsForValue()
            .set(getRefreshTokenKey(refreshTokenValue),
                RefreshTokenRedis(refreshTokenValue, clientDetails.clientId, clientDetails.clientAuthenticationMethod, accountId, accessTokenValue),
                Duration.ofSeconds(clientDetails.refreshTokenValidity))
            .publishOn(Schedulers.boundedElastic())
            .handle { it, sink ->
                if (!it) {
                    this.accessTokenRedisTemplate.delete(accessTokenValue).toFuture().get()
                    this.reactiveRedisTemplate.delete(
                        getClientIdMethodAccountIdKey(
                            clientDetails.clientId,
                            clientDetails.clientAuthenticationMethod,
                            accountId
                        )
                    ).toFuture().get()
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken"))
                    return@handle
                }
                sink.next(clientDetails)
            }

    }

    fun refreshToken(clientId: String, clientAuthenticationMethod: String, refreshTokenValue: String): Mono<Tokens> {
        return this.clientDetailsRepository.findByClientIdAndClientAuthenticationMethod(clientId, clientAuthenticationMethod)
            .switchIfEmpty { throw ResponseStatusException(HttpStatus.BAD_REQUEST, "fail to get ClientInfo") }
            .flatMap { clientDetails ->
                this.refreshTokenRedisTemplate.opsForValue()
                    .get(getRefreshTokenKey(refreshTokenValue))
                    .switchIfEmpty { throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid refreshToken") }
                    .flatMap { refreshToken ->
                        val accessTokenValue = UUID.randomUUID().toString()
                        val accountId = refreshToken.accountId
                        this.checkAccessTokenExist(refreshToken.accessToken)
                            .defaultIfEmpty(AccessTokenRedis(accessTokenValue, clientDetails, accountId, refreshTokenValue))
                            .flatMap {
                                if (it.value == accessTokenValue) {
                                    // accessToken 없음
                                    this.saveAccessToken(clientDetails, accessTokenValue, accountId, refreshTokenValue)
                                        .flatMap {
                                            this.saveAccountTokenMapping(clientDetails, accessTokenValue, accountId)
                                        }
                                } else {
                                    // accessToken 있음
                                    this.accessTokenRedisTemplate.opsForValue()
                                        .delete(getAccessTokenKey(it.value))
                                        .flatMap {
                                            this.accessTokenRedisTemplate.opsForValue()
                                                .delete(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId))
                                        }
                                        .flatMap {
                                            this.saveAccessToken(clientDetails, accessTokenValue, accountId, refreshTokenValue)
                                        }
                                        .flatMap {
                                            this.saveAccountTokenMapping(clientDetails, accessTokenValue, accountId)
                                        }
                                }
                            }
                            .map {
                                Tokens(
                                    BearerAccessToken(
                                        accessTokenValue,
                                        clientDetails.accessTokenValidity,
                                        Scope.parse(clientDetails.scopes)),
                                    RefreshToken(refreshTokenValue))
                            }
                    }
            }
    }

    fun checkAccessTokenExist(accessToken: String): Mono<AccessTokenRedis> {
        return this.accessTokenRedisTemplate.opsForValue()
            .get(getAccessTokenKey(accessToken))
    }
}