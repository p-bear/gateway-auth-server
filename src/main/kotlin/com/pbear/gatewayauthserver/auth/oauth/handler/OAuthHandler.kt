package com.pbear.gatewayauthserver.auth.oauth.handler

import com.nimbusds.common.contenttype.ContentType
import com.nimbusds.oauth2.sdk.AccessTokenResponse
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.util.URLUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import com.pbear.gatewayauthserver.auth.client.handler.ClientAuthenticationVerifierEncodeSupport
import com.pbear.gatewayauthserver.auth.oauth.service.TokenService
import mu.KotlinLogging
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono
import java.net.URL
import java.security.cert.X509Certificate
import java.util.stream.Collectors

@Component
class OAuthHandler(
    private val clientAuthenticationVerifierEncodeSupport: ClientAuthenticationVerifierEncodeSupport,
    private val tokenService: TokenService
) {
    private val log = KotlinLogging.logger {  }

    fun handleOauthToken(serverRequest: ServerRequest): Mono<ServerResponse> {
        return serverRequest.formData()
            .map { this.mapToHTTPRequest(serverRequest, it, null) }
            .map { TokenRequest.parse(it) }
            .doOnNext {

            }
            .zipWhen { Mono.just(ClientAuthentication.parse(it.toHTTPRequest())) }
            .doOnNext { this.clientAuthenticationVerifierEncodeSupport.verify(it.t2, null, null) }
            .flatMap { this.tokenService.getToken(it.t1, it.t2) }
            .flatMap{ ServerResponse.ok().bodyValue(AccessTokenResponse.parse(it.toJSONObject()).toJSONObject()) }
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
            request.query = serverRequest.queryParams()
                .map { "${it.key}=${it.value}" }
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