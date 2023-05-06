package com.pbear.gatewayauthserver.common.config

import io.netty.channel.ChannelOption
import io.netty.handler.timeout.ReadTimeoutHandler
import io.netty.handler.timeout.WriteTimeoutHandler
import org.springframework.boot.autoconfigure.web.WebProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import java.time.Duration
import java.util.concurrent.TimeUnit

@Configuration
class ResourceConfig {
    @Bean
    fun resources(): WebProperties.Resources = WebProperties.Resources()

    @Bean
    fun webClient(): WebClient = WebClient.builder()
        .clientConnector(ReactorClientHttpConnector(HttpClient.create()
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000)
            .responseTimeout(Duration.ofMillis(3000L))
            .doOnConnected {
                it.addHandlerLast(ReadTimeoutHandler(3000L, TimeUnit.MILLISECONDS))
                    .addHandlerLast(WriteTimeoutHandler(3000L, TimeUnit.MILLISECONDS))
            }))
        .build()
}