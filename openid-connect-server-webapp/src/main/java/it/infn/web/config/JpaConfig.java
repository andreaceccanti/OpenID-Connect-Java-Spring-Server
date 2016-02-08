package it.infn.web.config;

import java.util.Properties;

import org.eclipse.persistence.jpa.PersistenceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableTransactionManagement
@Import(IamConfig.class)
public class JpaConfig {

  @Autowired
  IamConfig iamConfig;

  @Bean
  public LocalContainerEntityManagerFactoryBean entityManagerFactory() {

    Properties jpaProperties = new Properties();
    jpaProperties.put("eclipselink.weaving", "false");
    jpaProperties.put("eclipselink.logging.level", "INFO");
    jpaProperties.put("eclipselink.logging.level.sql", "INFO");
    jpaProperties.put("eclipselink.cache.shared.default", "false");

    LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
    em.setPackagesToScan("org.mitre", "it.infn.web");
    em.setPersistenceProviderClass(PersistenceProvider.class);
    em.setDataSource(iamConfig.iamDataSource());
    em.setJpaVendorAdapter(iamConfig.jpaAdapter());
    em.setJpaProperties(jpaProperties);
    em.setPersistenceUnitName("defaultPersistenceUnit");

    return em;

  }

}
