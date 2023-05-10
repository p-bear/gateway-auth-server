package com.pbear.gatewayauthserver.auth.oauth

import com.pbear.gatewayauthserver.auth.client.ClientDetails
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

@Component
class TokenStore(private val oAuthRedisRepository: OAuthRedisRepository) {
    fun createAccessToken(accessTokenValue: String, refreshTokenValue: String, clientDetails: ClientDetails, accountId: Long): AccessTokenRedis {
        return AccessTokenRedis(accessTokenValue, clientDetails, accountId, refreshTokenValue)
    }

    fun saveAccessToken(accessTokenRedis: AccessTokenRedis): Mono<AccessTokenRedis> {
        return this.oAuthRedisRepository
            .saveAccessToken(accessTokenRedis)
            .handle { it, sink ->
                if (!it) {
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken"))
                    return@handle
                }
                sink.next(accessTokenRedis)
            }
            .flatMap { this.oAuthRedisRepository.saveAccountAccessTokenMapping(it) }
            .publishOn(Schedulers.boundedElastic())
            .handle { it, sink ->
                if (!it) {
                    this.oAuthRedisRepository.deleteAccessToken(accessTokenRedis.value).toFuture().get()
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
        return this.oAuthRedisRepository
            .saveRefreshToken(refreshTokenRedis)
            .publishOn(Schedulers.boundedElastic())
            .handle { it, sink ->
                if (!it) {
                    this.oAuthRedisRepository.deleteAccessToken(refreshTokenRedis.accessToken).toFuture().get()
                    this.oAuthRedisRepository.deleteAccountAccessTokenMapping( refreshTokenRedis.clientId, refreshTokenRedis.clientAuthenticationMethod, refreshTokenRedis.accountId).toFuture().get()
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save accessToken"))
                    return@handle
                }
                sink.next(refreshTokenRedis)
            }
    }

    fun getAccessToken(accessTokenValue: String): Mono<AccessTokenRedis> {
        return this.oAuthRedisRepository.getAccessToken(accessTokenValue)
    }

    fun getAccessToken(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<AccessTokenRedis> {
        return this.oAuthRedisRepository.getAccountAccessTokenMapping(clientId, clientAuthenticationMethod, accountId)
    }

    fun getRefreshToken(refreshTokenValue: String): Mono<RefreshTokenRedis> {
        return this.oAuthRedisRepository.getRefreshToken(refreshTokenValue)
    }

    fun deleteAccessToken(accessTokenRedis: AccessTokenRedis): Mono<Boolean> {
        return this.oAuthRedisRepository
            .deleteAccessToken(accessTokenRedis.value)
            .flatMap {
                this.oAuthRedisRepository.deleteAccountAccessTokenMapping(
                    accessTokenRedis.clientId,
                    accessTokenRedis.clientAuthenticationMethod,
                    accessTokenRedis.accountId)
            }
    }

    fun deleteRefreshToken(refreshTokenRedis: RefreshTokenRedis): Mono<Boolean> {
        return this.oAuthRedisRepository.deleteRefreshToken(refreshTokenRedis.value)
    }
}