package com.pbear.gatewayauthserver.auth.oauth

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.time.Duration

@Component
class OAuthRedisRepository(private val reactiveRedisTemplate: ReactiveRedisTemplate<String, String>,
                           @Qualifier("AccessTokenReactiveRedisTemplate")
                      private val accessTokenRedisTemplate: ReactiveRedisTemplate<String, AccessTokenRedis>,
                           @Qualifier("refreshTokenReactiveRedisTemplate")
                      private val refreshTokenRedisTemplate: ReactiveRedisTemplate<String, RefreshTokenRedis>
) {
    fun saveAccessToken(accessTokenRedis: AccessTokenRedis): Mono<Boolean> {
        return this.accessTokenRedisTemplate.opsForValue()
            .set(
                getAccessTokenKey(accessTokenRedis.value),
                accessTokenRedis,
                Duration.ofSeconds(accessTokenRedis.accessTokenValidity))
    }
    fun getAccessToken(accessTokenValue: String): Mono<AccessTokenRedis> {
        return this.accessTokenRedisTemplate.opsForValue().get(getAccessTokenKey(accessTokenValue))
    }
    fun deleteAccessToken(accessTokenValue: String): Mono<Boolean> {
        return this.accessTokenRedisTemplate.opsForValue().delete(accessTokenValue)
    }

    fun saveRefreshToken(refreshTokenRedis: RefreshTokenRedis): Mono<Boolean> {
        return this.refreshTokenRedisTemplate.opsForValue()
            .set(
                getRefreshTokenKey(refreshTokenRedis.value),
                refreshTokenRedis,
                Duration.ofSeconds(refreshTokenRedis.refreshTokenValidity))
    }
    fun getRefreshToken(refreshTokenValue: String): Mono<RefreshTokenRedis> {
        return this.refreshTokenRedisTemplate.opsForValue()
            .get(getRefreshTokenKey(refreshTokenValue))
    }
    fun deleteRefreshToken(refreshTokenValue: String): Mono<Boolean> {
        return this.refreshTokenRedisTemplate.opsForValue().delete(getRefreshTokenKey(refreshTokenValue))
    }

    fun saveAccountAccessTokenMapping(accessTokenRedis: AccessTokenRedis): Mono<Boolean> {
        return this.reactiveRedisTemplate.opsForValue()
            .set(
                getClientIdMethodAccountIdKey(accessTokenRedis.clientId, accessTokenRedis.clientAuthenticationMethod, accessTokenRedis.accountId),
                accessTokenRedis.value,
                Duration.ofSeconds(accessTokenRedis.accessTokenValidity))
    }
    fun getAccountAccessTokenMapping(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<AccessTokenRedis> {
        return this.reactiveRedisTemplate.opsForValue()
            .get(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId))
            .flatMap { this.getAccessToken(it) }
    }
    fun deleteAccountAccessTokenMapping(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<Boolean> {
        return this.reactiveRedisTemplate.opsForValue().delete(getClientIdMethodAccountIdKey(clientId, clientAuthenticationMethod, accountId))
    }

    fun saveAuthorizationCode(accountId: Long, authorizationCode: String, duration: Duration): Mono<Boolean> {
        return this.reactiveRedisTemplate.opsForValue()
            .set(getAuthorizationCodeKey(accountId), authorizationCode, duration)
    }
    fun getAuthorizationCode(accountId: Long): Mono<String> {
        return this.reactiveRedisTemplate.opsForValue()
            .get(getAuthorizationCodeKey(accountId))
    }



    companion object {
        private const val ACCESS_TOKEN_PREFIX = "accessToken"
        private const val CLIENT_ID_METHOD_ACCOUNT_ID_PREFIX = "clientIdMethodAccountId"
        private const val REFRESH_TOKEN_PREFIX = "refreshToken"
        private const val AUTHORIZATION_CODE = "authorizationCode"

        fun getAccessTokenKey(accessTokenValue: String): String {
            return "${ACCESS_TOKEN_PREFIX}_${accessTokenValue}"
        }

        fun getClientIdMethodAccountIdKey(clientId: String, clientAuthenticationMethod: String, accountId: Long): String {
            return "${CLIENT_ID_METHOD_ACCOUNT_ID_PREFIX}_${clientId}_${clientAuthenticationMethod}_${accountId}"
        }

        fun getRefreshTokenKey(refreshTokenValue: String): String {
            return "${REFRESH_TOKEN_PREFIX}_${refreshTokenValue}"
        }

        fun getAuthorizationCodeKey(accountId: Long): String {
            return "${AUTHORIZATION_CODE}_${accountId}"
        }
    }
}