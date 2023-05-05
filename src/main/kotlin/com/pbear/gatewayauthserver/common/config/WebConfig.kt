package com.pbear.gatewayauthserver.common.config

import org.springframework.boot.autoconfigure.web.WebProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ResourceConfig {
    @Bean
    fun resources(): WebProperties.Resources = WebProperties.Resources()
}