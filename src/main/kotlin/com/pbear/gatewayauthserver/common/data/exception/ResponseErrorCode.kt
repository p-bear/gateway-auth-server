package com.pbear.gatewayauthserver.common.data.exception

import org.springframework.http.HttpStatus

enum class ResponseErrorCode(
    val code: String,
    val httpStatus: HttpStatus,
    val message: String
) {
    COMMON_1("common.1", HttpStatus.INTERNAL_SERVER_ERROR, "Unknown Error")
}