package com.pbear.gatewayauthserver.auth.client.data.entity

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.Id
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.relational.core.mapping.Table
import java.time.LocalDateTime

@Table
data class ClientDetails(
    @Id
    var id: Long? = null,
    var clientId: String,
    var clientSecret: String,
    var clientAuthenticationMethod: String = ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
    var scopes: String = "test:*",
    var authorities: String = "USER",
    var grantTypes: String = GrantType.PASSWORD.value,
    var accessTokenValidity: Long = 86400,
    var refreshTokenValidity: Long = 2592000,

    @CreatedDate
    var creDate: LocalDateTime? = null,
    @LastModifiedDate
    var modDate: LocalDateTime? = null
)