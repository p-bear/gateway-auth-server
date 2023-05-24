package com.pbear.gatewayauthserver.auth.oauth.third

import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException

class GoogleAuthException(
    httpStatus: HttpStatus, responseMessage: String?, val code: String
): ResponseStatusException(httpStatus, responseMessage)