package com.pbear.gatewayauthserver.config

import io.r2dbc.spi.ConnectionFactories
import io.r2dbc.spi.ConnectionFactory
import io.r2dbc.spi.ConnectionFactoryOptions
import io.r2dbc.spi.Option
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.auditing.ReactiveIsNewAwareAuditingHandler
import org.springframework.data.mapping.context.PersistentEntities
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy
import org.springframework.data.r2dbc.core.R2dbcEntityOperations
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate
import org.springframework.data.r2dbc.dialect.MySqlDialect
import org.springframework.data.r2dbc.mapping.R2dbcMappingContext
import org.springframework.data.r2dbc.repository.config.EnableR2dbcRepositories
import org.springframework.r2dbc.core.DatabaseClient

@Configuration
@EnableR2dbcAuditing
class R2dbcCommonConfig {
    @Bean
    fun reactiveIsNewAwareAuditingHandler(r2dbcMappingContext: R2dbcMappingContext): ReactiveIsNewAwareAuditingHandler {
        return ReactiveIsNewAwareAuditingHandler(
            PersistentEntities.of(r2dbcMappingContext))
    }

    @Bean
    fun r2dbcMappingContext(): R2dbcMappingContext {
        return R2dbcMappingContext()
    }
}

@Configuration
@EnableR2dbcRepositories(
    basePackages = ["com.pbear.gatewayauthserver.auth.client"],
    entityOperationsRef = "mainMysqlR2dbcEntityOperations")
class R2dbcMainDBConfig {
    @Value("\${r2dbc.main.host}")
    val host: String = ""

    @Value("\${r2dbc.main.port}")
    val port: Int = -1

    @Value("\${r2dbc.main.username}")
    val username: String = ""

    @Value("\${r2dbc.main.password}")
    val password: String = ""

    @Bean
    @Qualifier("mainConnectionFactory")
    fun mainConnectionFactory(): ConnectionFactory = ConnectionFactories
        .get(ConnectionFactoryOptions.builder()
            .option(ConnectionFactoryOptions.SSL, true)
            .option(ConnectionFactoryOptions.DRIVER, "pool")
            .option(ConnectionFactoryOptions.PROTOCOL, "mariadb")
            .option(ConnectionFactoryOptions.HOST, host)
            .option(ConnectionFactoryOptions.PORT, port)
            .option(ConnectionFactoryOptions.USER, username)
            .option(ConnectionFactoryOptions.PASSWORD, password)
            .option(ConnectionFactoryOptions.DATABASE, "main")
            .option(Option.valueOf("initialSize"), 5)
            .option(Option.valueOf("maxSize"), 20)
            .option(Option.valueOf("validationQuery"), "select 1+1")
            .build())

    @Bean
    fun mainMysqlR2dbcEntityOperations(@Qualifier("mainConnectionFactory") connectionFactory: ConnectionFactory): R2dbcEntityOperations =
        R2dbcEntityTemplate(
            DatabaseClient.builder()
                .connectionFactory(connectionFactory)
                .build(),
            DefaultReactiveDataAccessStrategy(MySqlDialect.INSTANCE)
        )
}