package com.pbear.gatewayauthserver.auth.oauth

import com.pbear.gatewayauthserver.auth.client.ClientDetails
import com.pbear.gatewayauthserver.common.config.NoArg
import java.util.Date

@NoArg
data class AccessTokenRedis(
    val value: String,
    val issueTime: Long = Date().time,
    val clientId: String,
    val clientAuthenticationMethod: String,
    val accessTokenValidity: Long,
    val scopes: String,
    val authorities: String,
    val grantType: String,
    val accountId: Long,
    val refreshToken: String
) {
    constructor(accessTokenValue: String, clientDetails: ClientDetails, accountId: Long, refreshTokenValue: String): this(
        value = accessTokenValue,
        clientId = clientDetails.clientId,
        clientAuthenticationMethod = clientDetails.clientAuthenticationMethod,
        accessTokenValidity = clientDetails.accessTokenValidity,
        scopes = clientDetails.scopes,
        authorities = clientDetails.authorities,
        grantType = clientDetails.grantTypes,
        accountId = accountId,
        refreshToken = refreshTokenValue
    )
}

@NoArg
data class RefreshTokenRedis(
    val value: String,
    val clientId: String,
    val clientAuthenticationMethod: String,
    val accountId: Long,
    val accessToken: String,
    val refreshTokenValidity: Long
)

@NoArg
data class AuthorizationCodeRedis(
    val accountId: Long,
    val clientId: String,
    val clientAuthenticationMethod: String
)