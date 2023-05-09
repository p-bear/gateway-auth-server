package com.pbear.gatewayauthserver.common.config

import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.pbear.gatewayauthserver.auth.oauth.TokenStore
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty
import java.security.Principal

@Configuration
class SecurityConfig {
    companion object {
        private val permitAllApiMap = mapOf(
            HttpMethod.GET to listOf("/oauth/client", "/authorize"),
            HttpMethod.POST to listOf("/oauth/client", "/oauth/token", "/main/api/account"),
            HttpMethod.PUT to listOf("/oauth/client"),
            HttpMethod.DELETE to listOf("/oauth/client")
        )
    }

    @Bean
    fun securityWebFilterChain(
        serverHttpSecurity: ServerHttpSecurity,
        authManager: AuthManager,
        authenticationConverter: AuthenticationConverter): SecurityWebFilterChain {
        val filter = AuthenticationWebFilter(authManager)
        filter.setServerAuthenticationConverter(authenticationConverter)

        val authorizeExchangeSpec = serverHttpSecurity
            .authorizeExchange()
            // main 서버 기본 scope -> main:*
            .pathMatchers("/main/**").hasAuthority("SCOPE_main:*")

        // permitAll 세팅
        permitAllApiMap.forEach{ entry ->
            entry.value.forEach { uri ->
                authorizeExchangeSpec.pathMatchers(entry.key, uri).permitAll()
            }
        }

        return authorizeExchangeSpec
            .and()
            .addFilterAfter(filter, SecurityWebFiltersOrder.AUTHENTICATION)

            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .logout().disable()
            .cors().configurationSource(corsConfigurationSource())
            .and()
            .build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val config = CorsConfiguration()
        config.addAllowedOrigin("*")
        config.addAllowedHeader("*")
        config.addAllowedMethod("*")

        val configSource = UrlBasedCorsConfigurationSource()
        configSource.registerCorsConfiguration("/**", config)
        return configSource
    }

    @Bean
    fun userDetailsService(tokenStore: TokenStore): ReactiveUserDetailsService {
        return ReactiveUserDetailsService { name ->
            tokenStore.getAccessToken(name)
                .map { accessTokenRedis ->
                    User(
                        "${accessTokenRedis.accountId}",
                        accessTokenRedis.value,
                        Scope.parse(accessTokenRedis.scopes)
                            .map {
                                SimpleGrantedAuthority("SCOPE_${it.value}")
                            }
                            .plus(accessTokenRedis.authorities.split(",")
                                .map {
                                    SimpleGrantedAuthority("ROLE_$it")
                                }
                            )
                    ) as UserDetails
                }
                .switchIfEmpty { throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid accessToken") }
        }
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(4)
}

@Component
class AuthManager(private val userDetailsService: ReactiveUserDetailsService): ReactiveAuthenticationManager {
    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        if (authentication.isAuthenticated) {
            return Mono.just(authentication)
        }
        return this.userDetailsService.findByUsername(authentication.name)
            .map {
                UsernamePasswordAuthenticationToken(it.username, it.password, it.authorities)
            }
    }
}

@Component
class AuthenticationConverter: ServerAuthenticationConverter {
    override fun convert(exchange: ServerWebExchange): Mono<Authentication> {
        if (exchange.request.uri.path.equals("/oauth/token")) {
            return Mono.just(UsernamePasswordAuthenticationToken.authenticated(null, null, null))
        }
        val token = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
        val accessToken = BearerAccessToken.parse(token, AccessTokenType.BEARER)
        return Mono.just(UsernamePasswordAuthenticationToken.unauthenticated(TokenPrincipal(accessToken), accessToken))
    }
}

class TokenPrincipal(private val accessToken: AccessToken): Principal {
    override fun getName(): String {
        return this.accessToken.value
    }
}