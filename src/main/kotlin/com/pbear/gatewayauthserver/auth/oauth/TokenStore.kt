package com.pbear.gatewayauthserver.auth.oauth

import com.pbear.gatewayauthserver.auth.client.ClientDetails
import com.pbear.gatewayauthserver.auth.client.ClientHandler
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import reactor.kotlin.core.publisher.switchIfEmpty
import java.util.UUID

@Component
class TokenStore(
    private val oAuthRedisRepository: OAuthRedisRepository,
    private val clientHandler: ClientHandler
) {
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

    fun createSaveAccessToken(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<AccessTokenRedis> {
        return this.clientHandler.getClient(clientId, clientAuthenticationMethod)
            .map { this.createAccessToken(UUID.randomUUID().toString(), "none", it, accountId) }
            .flatMap { this.saveAccessToken(it) }
    }

    fun createSaveAccessTokenRefreshToken(clientId: String, clientAuthenticationMethod: String, accountId: Long): Mono<AccessTokenRedis> {
        return this.clientHandler.getClient(clientId, clientAuthenticationMethod)
            .zipWhen { clientDetails ->
                val accessTokenRedis = this.createAccessToken(UUID.randomUUID().toString(), UUID.randomUUID().toString(), clientDetails, accountId)
                this.saveAccessToken(accessTokenRedis)
            }
            .zipWhen {
                val refreshTokenRedis = this.createRefreshToken(
                    it.t2.value,
                    it.t2.refreshToken,
                    it.t1,
                    it.t2.accountId)
                this.saveRefreshToken(refreshTokenRedis)
            }
            .map { it.t1.t2 }
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

    fun getAccessTokenByAuthorizationCode(authorizationCode: String): Mono<AccessTokenRedis> {
        return this.oAuthRedisRepository.getAuthorizationCode(authorizationCode)
            .switchIfEmpty { throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid authorizationCode") }
            .flatMap { this.createSaveAccessTokenRefreshToken(it.clientId, it.clientAuthenticationMethod, it.accountId) }
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

    fun getRefreshToken(refreshTokenValue: String): Mono<RefreshTokenRedis> {
        return this.oAuthRedisRepository.getRefreshToken(refreshTokenValue)
    }

    fun deleteRefreshToken(refreshTokenRedis: RefreshTokenRedis): Mono<Boolean> {
        return this.oAuthRedisRepository.deleteRefreshToken(refreshTokenRedis.value)
    }

    fun saveGoogleAccessToken(accessTokenValue: String, scope: String, expiresIn: Long,
                              accountId: Long, clientId: String, clientAuthenticationMethod: String): Mono<GoogleAccessTokenRedis> {
        val googleAccessTokenRedis = GoogleAccessTokenRedis(
            accessToken = accessTokenValue,
            scope = scope,
            accountId = accountId,
            clientId = clientId,
            clientAuthenticationMethod = clientAuthenticationMethod,
            expiresIn = expiresIn)
        return this.oAuthRedisRepository.saveGoogleAccessToken(googleAccessTokenRedis)
            .handle { it, sink ->
                if (!it) {
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save google accessToken"))
                    return@handle
                }
                sink.next(googleAccessTokenRedis)
            }
    }

    fun getGoogleAccessToken(accountId: Long): Mono<GoogleAccessTokenRedis> {
        return this.oAuthRedisRepository.getGoogleAccessToken(accountId)
    }
}