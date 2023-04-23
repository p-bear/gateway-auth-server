package com.pbear.gatewayauthserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class GatewayAuthServerApplication

fun main(args: Array<String>) {
    runApplication<GatewayAuthServerApplication>(*args)
}
