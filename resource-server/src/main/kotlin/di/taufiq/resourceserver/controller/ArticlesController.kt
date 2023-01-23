package di.taufiq.resourceserver.controller

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ArticlesController {

    @GetMapping("/hello-user")
    @PreAuthorize("hasAuthority('USER')")
    fun helloUser(): String {
        return "hello user"
    }

    @GetMapping("/hello-user")
    @PreAuthorize("hasAuthority('ADMIN')")
    fun helloAdmin(): String {
        return "hello-admin"
    }

}
