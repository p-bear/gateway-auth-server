package com.pbear.gatewayauthserver.auth.oauth.data.entity

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
)

@NoArg
data class RefreshTokenRedis(
    val value: String,
    val clientId: String,
    val clientAuthenticationMethod: String,
    val accountId: Long
)