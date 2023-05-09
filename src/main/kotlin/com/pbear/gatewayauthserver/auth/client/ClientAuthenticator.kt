package com.pbear.gatewayauthserver.auth.client

import com.nimbusds.jose.JWSHeader
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.auth.verifier.*
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.id.ClientID
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import java.security.PublicKey

@Component
class ClientAuthenticationVerifierEncodeSupport(
    private val passwordEncoder: PasswordEncoder,
    databaseClientCredentialsSelector: DatabaseClientCredentialsSelector,
): ClientAuthenticationVerifier<ClientDetails>(
    databaseClientCredentialsSelector, setOf(Audience("TO_BE_CREATE"))
) {

    override fun verify(clientAuth: ClientAuthentication, hints: MutableSet<Hint>?, context: Context<ClientDetails>?) {
        when (clientAuth) {
            is PlainClientSecret -> this.verifyPlainClientSecret(clientAuth, context)
            else -> super.verify(clientAuth, hints, context)
        }
    }

    private fun verifyPlainClientSecret(clientAuth: ClientAuthentication, context: Context<ClientDetails>?) {
        // Secret From DB
        val secretCandidates = clientCredentialsSelector
            .selectClientSecrets(clientAuth.clientID, clientAuth.method, context)
            .filterNotNull()
            .ifEmpty {
                throw InvalidClientException.NO_REGISTERED_SECRET
            }

        val plainAuth = clientAuth as PlainClientSecret

        for (candidate in secretCandidates) {
            if (passwordEncoder.matches(plainAuth.clientSecret.value, candidate.value)) {
                return
            }
        }

        throw InvalidClientException.BAD_SECRET
    }
}


@Component
class DatabaseClientCredentialsSelector(
    val clientDetailsRepository: ClientDetailsRepository
): ClientCredentialsSelector<ClientDetails> {
    override fun selectClientSecrets(
        claimedClientID: ClientID,
        authMethod: ClientAuthenticationMethod,
        context: Context<ClientDetails>?
    ): MutableList<Secret> {
        val result = this.clientDetailsRepository
            .findByClientIdAndClientAuthenticationMethod(claimedClientID.value, authMethod.value)
            .toFuture()
            .get()
        return when (result) {
            null -> mutableListOf()
            else -> mutableListOf(Secret(result.clientSecret))
        }
    }

    override fun selectPublicKeys(
        claimedClientID: ClientID?,
        authMethod: ClientAuthenticationMethod?,
        jwsHeader: JWSHeader?,
        forceRefresh: Boolean,
        context: Context<ClientDetails>?
    ): MutableList<out PublicKey> {
        return mutableListOf()
    }
}