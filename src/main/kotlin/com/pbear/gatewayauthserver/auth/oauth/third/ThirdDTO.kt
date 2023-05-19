package com.pbear.gatewayauthserver.auth.oauth.third

import com.pbear.gatewayauthserver.common.config.NoArg

@NoArg
data class ReqPostOAuthTokenGoogle(
    val code: String
)

@NoArg
data class ResGooglePostOauthToken(
    val access_token: String,
    val expires_in: Int,
    val token_type: String,
    val scope: String,
    val id_token: String,
    val refresh_token: String?
)

@NoArg
data class ResMainGetAccountGoogle(
    val result: String,
    val data: ResMainGetAccountGoogleData
)

data class ResMainGetAccountGoogleData(
    val id: Long,
    val googleId: String,
    val accountId: Long,
    val email: String,
    val name: String,
    val givenName: String,
    val verifiedEmail: Boolean
)

@NoArg
data class ReqMainPostAccountGoogle(
    val googleId: String,
    val accountId: Long,
    val email: String,
    val name: String,
    val givenName: String,
    val verifiedEmail: Boolean,
    val scope: String,
    val refreshToken: String
)