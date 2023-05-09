package com.pbear.gatewayauthserver.auth.oauth

import com.pbear.gatewayauthserver.auth.client.ClientDetails
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.time.Duration

@Component
class TokenStore(
    private val reactiveRedisTemplate: ReactiveRedisTemplate<String, String>,
    @Qualifier("AccessTokenReactiveRedisTemplate")
    private val accessTokenRedisTemplate: ReactiveRedisTemplate<String, AccessTokenRedis>,
    @Qualifier("refreshTokenReactiveRedisTemplate")
    private val refreshTokenRedisTemplate: ReactiveRedisTemplate<String, RefreshTokenRedis>
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

    fun createAccessToken(accessTokenValue: String, refreshTokenValue: String, clientDetails: ClientDetails, accountId: Long): AccessTokenRedis {
        return AccessTokenRedis(accessTokenValue, clientDetails, accountId, refreshTokenValue)
    }

    fun saveAccessToken(accessTokenRedis: AccessTokenRedis): Mono<AccessTokenRedis> {
        return this.accessTokenRedisTemplate.opsForValue()
            .set(
                getAccessTokenKey(accessTokenRedis.value),
                accessTokenRedis,
                Duration.ofSeconds(accessTokenRedis.accessTokenValidity))
            .handle { it, sink ->
                if (!it) {
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken"))
                    return@handle
                }
                sink.next(accessTokenRedis)
            }
            .flatMap { this.reactiveRedisTemplate.opsForValue()
                .set(
                    getClientIdMethodAccountIdKey(accessTokenRedis.clientId, accessTokenRedis.clientAuthenticationMethod, accessTokenRedis.accountId),
                    accessTokenRedis.value,
                    Duration.ofSeconds(accessTokenRedis.accessTokenValidity))
            }
            .publishOn(Schedulers.boundedElastic())
            .handle { it, sink ->
                if (!it) {
                    this.accessTokenRedisTemplate.delete(accessTokenRedis.value).toFuture().get()
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken mapping"))
                    return@handle
                }
                sink.next(accessTokenRedis)
            }
    }

    fun createRefreshToken(accessTokenValue: String, refreshTokenValue: String, clientDetails: ClientDetails, accountId: Long): RefreshTokenRedis {
        return RefreshTokenRedis(
            refreshTokenValue,
            clientDetails.clientId,
            clientDetails.clientAuthenticationMethod,
            accountId,
            accessTokenValue,
            clientDetails.refreshTokenValidity)
    }

    fun saveRefreshToken(refreshTokenRedis: RefreshTokenRedis): Mono<RefreshTokenRedis> {
        return this.refreshTokenRedisTemplate.opsForValue()
            .set(
                getRefreshTokenKey(refreshTokenRedis.value),
                refreshTokenRedis,
                Duration.ofSeconds(refreshTokenRedis.refreshTokenValidity))
            .publishOn(Schedulers.boundedElastic())
            .handle { it, sink ->
                if (!it) {
                    this.accessTokenRedisTemplate.delete(refreshTokenRedis.accessToken).toFuture().get()
                    this.reactiveRedisTemplate.delete(
                        getClientIdMethodAccountIdKey(
                            refreshTokenRedis.clientId,
                            refreshTokenRedis.clientAuthenticationMethod,
                            refreshTokenRedis.accountId))
                        .toFuture().get()
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken"))
                    return@handle
                }
                sink.next(refreshTokenRedis)
            }
    }

    fun getAccessToken(accessTokenValue: String): Mono<AccessTokenRedis> {
        return this.accessTokenRedisTemplate.opsForValue()
            .get(getAccessTokenKey(accessTokenValue))
    }

    fun getAccessToken(
        clientId: String,
        clientAuthenticationMethod: String,
        accountId: Long
    ): Mono<AccessTokenRedis> {
        return this.reactiveRedisTemplate.opsForValue()
            .get(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId))
            .flatMap { this.getAccessToken(it) }
    }

    fun getRefreshToken(refreshTokenValue: String): Mono<RefreshTokenRedis> {
        return this.refreshTokenRedisTemplate.opsForValue()
            .get(getRefreshTokenKey(refreshTokenValue))
    }

    fun deleteAccessToken(accessTokenRedis: AccessTokenRedis): Mono<Boolean> {
        return this.accessTokenRedisTemplate.opsForValue()
            .delete(getAccessTokenKey(accessTokenRedis.value))
            .flatMap {
                this.reactiveRedisTemplate.opsForValue()
                    .delete(getClientIdMethodAccountIdKey(accessTokenRedis.clientId, accessTokenRedis.clientAuthenticationMethod, accessTokenRedis.accountId))
            }
    }

    fun deleteRefreshToken(refreshTokenRedis: RefreshTokenRedis): Mono<Boolean> {
        return this.refreshTokenRedisTemplate.opsForValue()
            .delete(getRefreshTokenKey(refreshTokenRedis.value))
    }
}