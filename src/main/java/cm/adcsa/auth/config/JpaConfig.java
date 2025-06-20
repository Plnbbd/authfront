package cm.adcsa.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableJpaRepositories(basePackages = "cm.adcsa.auth.repository")
@EnableTransactionManagement
public class JpaConfig {
}