package com.pbear.gatewayauthserver.auth.oauth

import com.nimbusds.common.contenttype.ContentType
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.util.URLUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import com.pbear.gatewayauthserver.auth.client.ClientAuthenticationVerifierEncodeSupport
import com.pbear.gatewayauthserver.auth.client.ClientHandler
import com.pbear.gatewayauthserver.common.WebClientService
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.UUID
import java.util.stream.Collectors

@Component
class OAuthHandler(
    private val clientVerifier: ClientAuthenticationVerifierEncodeSupport,
    private val tokenService: TokenService,
    private val webClientService: WebClientService,
    private val oAuthRedisRepository: OAuthRedisRepository,
    private val clientHandler: ClientHandler,
    private val tokenStore: TokenStore
) {
    private val log = KotlinLogging.logger {  }

    @Value("\${login.redirect.url}")
    val loginRedirectUrl: String = ""


    fun handleOauthToken(serverRequest: ServerRequest): Mono<ServerResponse> {
        return serverRequest.formData()
            .map { this.mapToHTTPRequest(serverRequest, it, null) }
            .map { TokenRequest.parse(it) }
            .zipWhen { Mono.just(ClientAuthentication.parse(it.toHTTPRequest())) }
            .doOnNext { this.clientVerifier.verify(it.t2, null, null) }
            .flatMap { this.tokenService.getToken(it.t1, it.t2) }
            .flatMap{ ServerResponse.ok().bodyValue(AccessTokenResponse.parse(it.toJSONObject()).toJSONObject()) }
    }

    fun handleGetAuthorize(serverRequest: ServerRequest): Mono<ServerResponse> {
        return serverRequest.formData()
            .map { this.mapToHTTPRequest(serverRequest, it, null) }
            .flatMap {
                val authorizationRequest = AuthorizationRequest.parse(it)
                when (authorizationRequest.responseType) {
                    ResponseType.CODE -> this.handleAuthorizeCode(it, authorizationRequest)
                    ResponseType.TOKEN -> this.handleAuthorizeToken(authorizationRequest)
                    else -> return@flatMap Mono.error(ResponseStatusException(HttpStatus.BAD_REQUEST, "response_type not supported, responseType: ${authorizationRequest.responseType}"))
                }
            }
    }

    private fun handleAuthorizeCode(httpRequest: HTTPRequest, authorizationRequest: AuthorizationRequest): Mono<ServerResponse> {
        val clientAuthentication = ClientAuthentication.parse(httpRequest)
        this.clientVerifier.verify(clientAuthentication, null, null)

        if (authorizationRequest.customParameters["username"] == null || authorizationRequest.customParameters["password"] == null) {
            return ServerResponse.status(HttpStatus.PERMANENT_REDIRECT)
                .header(HttpHeaders.LOCATION, this.loginRedirectUrl)
                .build()
        }

        val authorizationCode = UUID.randomUUID().toString()
        return this.webClientService
            .postCheckAccountPassword(authorizationRequest.customParameters["username"]!![0], authorizationRequest.customParameters["password"]!![0])
            .zipWhen { accountPasswordResponse ->
                this.clientHandler.getClient(clientAuthentication.clientID.value, clientAuthentication.method.value)
                    .flatMap { clientDetails ->
                        this.oAuthRedisRepository.saveAuthorizationCode(
                            authorizationCode,
                            AuthorizationCodeRedis(
                                (accountPasswordResponse["id"] as Int).toLong(),
                                clientDetails.clientId,
                                clientDetails.clientAuthenticationMethod),
                            Duration.ofSeconds(60L))
                    }
            }
            .handle { it, sink ->
                if (!it.t2) {
                    sink.error(ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "fail to save authorizationCode"))
                    return@handle
                }
                sink.next(it.t1)
            }
            .map {
                val redirectParameter = mutableMapOf(
                    "code" to mutableListOf(authorizationCode),
                    "accountId" to mutableListOf((it["id"] as Int).toString())
                )
                if (authorizationRequest.state?.value != null) {
                    redirectParameter["state"] = mutableListOf(authorizationRequest.state.value)
                }
                AuthorizationSuccessResponse.parse(authorizationRequest.redirectionURI ?: URI(this.loginRedirectUrl), redirectParameter)
            }
            .flatMap {
                ServerResponse
                    .status(HttpStatus.PERMANENT_REDIRECT)
                    .header(HttpHeaders.LOCATION, it.toURI().toString())
                    .build()
            }
    }

    private fun handleAuthorizeToken(authorizationRequest: AuthorizationRequest): Mono<ServerResponse> {
        if (authorizationRequest.customParameters["username"] == null || authorizationRequest.customParameters["password"] == null) {
            return ServerResponse.status(HttpStatus.PERMANENT_REDIRECT)
                .header(HttpHeaders.LOCATION, this.loginRedirectUrl)
                .build()
        }

        if (authorizationRequest.clientID.value.isNullOrEmpty() || authorizationRequest.customParameters["client_authentication_method"].isNullOrEmpty()) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "clien_id and client_authentication_method required")
        }

        if (authorizationRequest.redirectionURI == null) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "redirect_uri required")
        }

        return this.webClientService.postCheckAccountPassword(authorizationRequest.customParameters["username"]!![0], authorizationRequest.customParameters["password"]!![0])
            .zipWhen { this.clientHandler.getClient(authorizationRequest.clientID.value, authorizationRequest.customParameters["client_authentication_method"]!![0]) }
            .doOnNext {
                if (authorizationRequest.redirectionURI.toString() != it.t2.redirectUri) {
                    throw ResponseStatusException(HttpStatus.BAD_REQUEST, "redirect_uri not match")
                }
            }
            .zipWhen {
                this.tokenStore.createSaveAccessTokenRefreshToken(
                    authorizationRequest.clientID.value,
                    authorizationRequest.customParameters["client_authentication_method"]!![0],
                    (it.t1["id"] as Int).toLong())
            }
            .map {
                val redirectParameter = mutableMapOf(
                    "access_token" to mutableListOf(it.t2.value),
                    "token_type" to mutableListOf(AccessTokenType.BEARER.value),
                    "accountId" to mutableListOf(it.t2.accountId.toString())
                )
                if (authorizationRequest.state?.value != null) {
                    redirectParameter["state"] = mutableListOf(authorizationRequest.state.value)
                }

                AuthorizationSuccessResponse.parse(URI(it.t1.t2.redirectUri), redirectParameter)
            }
            .flatMap {
                ServerResponse
                    .status(HttpStatus.PERMANENT_REDIRECT)
                    .header(HttpHeaders.LOCATION, it.toURI().toString())
                    .build()
            }
    }

    private fun <T> mapToHTTPRequest(serverRequest: ServerRequest, formData: MultiValueMap<String, String>?, body: T?): HTTPRequest {
        val method = HTTPRequest.Method.valueOf(serverRequest.methodName().uppercase())

        val url: URL = serverRequest.uri().toURL()

        val request = HTTPRequest(method, url)

        val reqContentType = serverRequest.headers().contentType()
            .orElseThrow{ IllegalArgumentException("no Content-Type header value") }

        try {
            request.setContentType(reqContentType.toString())
        } catch (e: ParseException) {
            throw IllegalArgumentException("Invalid Content-Type header value: " + e.message, e)
        }

        serverRequest.headers().asHttpHeaders().entries
            .filter { it.value != null }
            .forEach {
                request.setHeader(it.key, *it.value.toTypedArray<String>())
            }

        if (method == HTTPRequest.Method.GET || method == HTTPRequest.Method.DELETE) {
            val queryParams = LinkedMultiValueMap<String, String>()
            queryParams.addAll(serverRequest.queryParams())
            if (formData != null) queryParams.addAll(formData)
            request.query = queryParams
                .map { "${it.key}=${it.value[0]}" }
                .stream()
                .collect(Collectors.joining("&"))
        } else if (method == HTTPRequest.Method.POST || method == HTTPRequest.Method.PUT) {
            if (ContentType.APPLICATION_URLENCODED.matches(request.entityContentType)) {
                if (formData != null) {
                    request.query = URLUtils.serializeParameters(formData.entries.stream()
                        .collect(Collectors.toMap(Map.Entry<String, List<String>>::key, Map.Entry<String, List<String>>::value)))
                }
            } else {
                request.query = body.toString()
            }
        }

        // Extract validated client X.509 if we have mutual TLS
        val cert = extractClientX509Certificate(serverRequest)
        if (cert != null) {
            request.clientX509Certificate = cert
            request.clientX509CertificateSubjectDN = if (cert.subjectDN != null) cert.subjectDN.name else null

            // The root DN cannot be reliably set for a CA-signed
            // client cert from a servlet request, unless self-issued
            if (X509CertificateUtils.hasMatchingIssuerAndSubject(cert)) {
                request.clientX509CertificateRootDN = if (cert.issuerDN != null) cert.issuerDN.name else null
            }
        }

        // Extract client IP address
        serverRequest.remoteAddress().ifPresent {
            request.clientIPAddress = it.toString()
        }

        return request
    }

    private fun extractClientX509Certificate(serverRequest: ServerRequest): X509Certificate? {
        val optionalCerts = serverRequest.attribute("javax.servlet.request.X509Certificate")
        return if (optionalCerts.isEmpty) {
            null
        } else {
            (optionalCerts.get() as Array<*>)[0] as X509Certificate
        }
    }

}