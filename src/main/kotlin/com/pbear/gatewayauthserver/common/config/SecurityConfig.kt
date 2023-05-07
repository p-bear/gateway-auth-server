package com.pbear.gatewayauthserver.common.config

import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.pbear.gatewayauthserver.auth.oauth.service.TokenService
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
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty
import java.security.Principal

@Configuration
class SecurityConfig {
    @Bean
    fun securityWebFilterChain(
        serverHttpSecurity: ServerHttpSecurity,
        authManager: AuthManager,
        authenticationConverter: AuthenticationConverter): SecurityWebFilterChain {
        val filter = AuthenticationWebFilter(authManager)
        filter.setServerAuthenticationConverter(authenticationConverter)

        return serverHttpSecurity
            .authorizeExchange()
            .pathMatchers("/main/**").hasAuthority("SCOPE_main:*")
            .pathMatchers("/oauth/client").permitAll()
            .pathMatchers(HttpMethod.POST, "/oauth/token").permitAll()

            .and()
            .addFilterAfter(filter, SecurityWebFiltersOrder.AUTHENTICATION)

            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .logout().disable()
            .cors().disable()
            .build()
    }

    @Bean
    fun userDetailsService(tokenService: TokenService): ReactiveUserDetailsService {
        return ReactiveUserDetailsService { name ->
            tokenService.checkAccessTokenExist(name)
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
        return this.userDetailsService.findByUsername(authentication.name)
            .map {
                UsernamePasswordAuthenticationToken(it.username, it.password, it.authorities)
            }
    }
}

@Component
class AuthenticationConverter: ServerAuthenticationConverter {
    override fun convert(exchange: ServerWebExchange): Mono<Authentication> {
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