package di.taufiq.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain


@Configuration
class SecurityConfig {

    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http
            .csrf().disable()
            .cors().disable()
            .formLogin()
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService? {
        val userDetails: UserDetails = User.withDefaultPasswordEncoder()
            .username("user")
            .password("user")
            .authorities("USER")
            .build()
        return InMemoryUserDetailsManager(userDetails)
    }

}
