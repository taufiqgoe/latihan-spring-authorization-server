package di.taufiq.resourceserver.controller

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ArticlesController {

    @GetMapping("/articles")
    @PreAuthorize("hasAuthority('ADMIN')")
    fun getArticles(): Array<String>? {
        return arrayOf("Article 1", "Article 2", "Article 3")
    }

}
