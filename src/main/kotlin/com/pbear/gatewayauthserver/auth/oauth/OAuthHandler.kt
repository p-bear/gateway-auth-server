package com.pbear.gatewayauthserver.auth.oauth

import com.nimbusds.common.contenttype.ContentType
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.Tokens
import com.nimbusds.oauth2.sdk.util.URLUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import com.pbear.gatewayauthserver.auth.client.ClientAuthenticationVerifierEncodeSupport
import com.pbear.gatewayauthserver.auth.client.ClientHandler
import com.pbear.gatewayauthserver.auth.oauth.third.GoogleAuthService
import com.pbear.gatewayauthserver.auth.oauth.third.ReqMainPostAccountGoogle
import com.pbear.gatewayauthserver.auth.oauth.third.ReqPostOAuthTokenGoogle
import com.pbear.gatewayauthserver.auth.oauth.third.ResGooglePostOauthToken
import com.pbear.gatewayauthserver.common.WebClientService
import com.pbear.gatewayauthserver.common.config.CustomUserDetail
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.ReactiveSecurityContextHolder
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
    private val tokenStore: TokenStore,
    private val googleAuthService: GoogleAuthService
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

    fun handlePostOAuthTokenGoogle(serverRequest: ServerRequest): Mono<ServerResponse> {
        return serverRequest.bodyToMono(ReqPostOAuthTokenGoogle::class.java)
            .flatMap {
                this.googleAuthService.getMainGoogleAuthInfo(it.code)
                    .onErrorMap { throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "google auth fail") }
            }
            .zipWhen { ReactiveSecurityContextHolder.getContext()
                .map { (it.authentication.credentials as CustomUserDetail).getAccessTokenRedis() }}
            .flatMap { this.upgradeAccessTokenWithGoogle(it.t1, it.t2) }
            .flatMap { ServerResponse.ok().bodyValue(AccessTokenResponse.parse(it.toJSONObject()).toJSONObject()) }
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
                AuthorizationSuccessResponse(
                    URI(it.t1.t2.redirectUri),
                    null,
                    BearerAccessToken(it.t2.value),
                    State.parse(authorizationRequest.state.value),
                    ResponseMode.QUERY)
            }
            .flatMap {
                ServerResponse
                    .status(HttpStatus.PERMANENT_REDIRECT)
                    .header(HttpHeaders.LOCATION, it.toURI().toString())
                    .build()
            }
    }

    private fun upgradeAccessTokenWithGoogle(resGooglePostOauthToken: ResGooglePostOauthToken, accessTokenRedis: AccessTokenRedis): Mono<Tokens> {

        val jWTClaimsSet = this.extractJwtIdTokenPayload(resGooglePostOauthToken.id_token)
        return this.webClientService.getAccountGoogle(jWTClaimsSet.subject)
            .onErrorResume { _ ->
                log.info("google account not linked >> add google account to accountId: ${accessTokenRedis.accountId}")
                this.webClientService.postAccountGoogle(ReqMainPostAccountGoogle(
                    jWTClaimsSet.subject,
                    accessTokenRedis.accountId,
                    jWTClaimsSet.getStringClaim("email"),
                    jWTClaimsSet.getStringClaim("name"),
                    jWTClaimsSet.getStringClaim("given_name"),
                    jWTClaimsSet.getBooleanClaim("email_verified"),
                    resGooglePostOauthToken.scope,
                    resGooglePostOauthToken.refresh_token ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "google refreshToken required")))
                    .onErrorMap { throw ResponseStatusException(HttpStatus.BAD_REQUEST, "google linked already") }
            }
            .flatMap { this.tokenService.upgradeAccessToken(accessTokenRedis, resGooglePostOauthToken) }
            .map { this.tokenService.mapToTokens(accessTokenRedis.value, accessTokenRedis.issueTime, accessTokenRedis.accessTokenValidity, accessTokenRedis.scopes, accessTokenRedis.refreshToken) }
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

    private fun extractJwtIdTokenPayload(jwt: String): JWTClaimsSet {
        return JWTParser.parse(jwt).jwtClaimsSet
    }
}