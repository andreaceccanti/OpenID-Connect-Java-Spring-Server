package it.infn.web.config;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import org.eclipse.persistence.jpa.PersistenceProvider;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.config.JsonMessageSource;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.mitre.openid.connect.service.impl.DefaultApprovedSiteService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.DatabasePopulatorUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.nimbusds.jose.JWEAlgorithm;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

@Configuration
@EnableAsync
@EnableScheduling
public class IamConfig {

  @Value("${spring.application.issuer}")
  private String issuer;

  @Value("${spring.application.logoImageUrl}")
  private String logoImageUrl;

  @Value("${spring.application.topbarTitle}")
  private String topbarTitle;

  @Value("${spring.datasource.driverClassName}")
  private String dbDriverClassName;

  @Value("${spring.datasource.url}")
  private String dbUrl;

  @Value("${spring.datasource.username}")
  private String dbUsername;

  @Value("${spring.datasource.password}")
  private String dbPassword;

  @Value("${spring.datasource.databasePlatform}")
  private String dbPlatform;

  @Bean
  public OAuth2TokenEntityService tokenService() {

    return new DefaultOAuth2ProviderTokenService();
  }

  @Bean
  public ApprovedSiteService siteService() {

    return new DefaultApprovedSiteService();
  }

  @Bean
  public DefaultOAuth2AuthorizationCodeService codeService() {

    return new DefaultOAuth2AuthorizationCodeService();
  }

  // server-config.xml
  @Bean
  public ConfigurationPropertiesBean configBean() {

    ConfigurationPropertiesBean config = new ConfigurationPropertiesBean();
    config.setIssuer(issuer);
    config.setLogoImageUrl(logoImageUrl);
    config.setTopbarTitle(topbarTitle);
    config.setRegTokenLifeTime(172800L);
    config.setForceHttps(false);
    config.setLocale(Locale.ENGLISH);

    return config;
  }

  // data-context.xml
  @Bean
  public DataSource iamDataSource() {

    Properties props = new Properties();
    props.setProperty("driverClassName", dbDriverClassName);
    props.setProperty("jdbcUrl", dbUrl);
    props.setProperty("username", dbUsername);
    props.setProperty("password", dbPassword);

    HikariConfig config = new HikariConfig(props);
    DataSource dataSource = new HikariDataSource(config);

    DatabasePopulatorUtils.execute(createDatabasePopulator(), dataSource);

    return dataSource;
  }

  private DatabasePopulator createDatabasePopulator() {

    ResourceDatabasePopulator databasePopulator = new ResourceDatabasePopulator();
    databasePopulator.setContinueOnError(false);
    databasePopulator.addScript(new ClassPathResource("database_tables.sql"));
    databasePopulator.addScript(new ClassPathResource("security-schema.sql"));
    databasePopulator
      .addScript(new ClassPathResource("loading_temp_tables.sql"));
    databasePopulator.addScript(new ClassPathResource("users.sql"));
    databasePopulator.addScript(new ClassPathResource("clients.sql"));
    databasePopulator.addScript(new ClassPathResource("scopes.sql"));
    return databasePopulator;
  }

  @Bean
  public JpaVendorAdapter jpaAdapter() {

    EclipseLinkJpaVendorAdapter jpaAdapter = null;
    jpaAdapter = new EclipseLinkJpaVendorAdapter();
    jpaAdapter.setDatabasePlatform(dbPlatform);
    jpaAdapter.setShowSql(true);

    return jpaAdapter;
  }

  // authz-config.xml
  @Bean
  public AccessDeniedHandler oauthAccessDeniedHandler() {

    return new OAuth2AccessDeniedHandler();
  }

  @Bean
  public MessageSource messageSource() {

    JsonMessageSource messageSource = new JsonMessageSource();
    messageSource
      .setBaseDirectory(new FileSystemResource("/resource/js/locale"));
    messageSource.setUseCodeAsDefaultMessage(true);

    return messageSource;
  }

  // jpa-config.xml
  @Bean
  public JpaTransactionManager transactionManager() {

    JpaTransactionManager transactionManager = new JpaTransactionManager();
    transactionManager.setEntityManagerFactory(entityManagerFactory());

    return transactionManager;
  }

  @Bean
  public EntityManagerFactory entityManagerFactory() {

    Map<String, Object> jpaProperties = new LinkedHashMap<String, Object>();
    jpaProperties.put("eclipselink.weaving", false);
    jpaProperties.put("eclipselink.logging.level", "INFO");
    jpaProperties.put("eclipselink.logging.level.sql", "INFO");
    jpaProperties.put("eclipselink.cache.shared.default", false);

    LocalContainerEntityManagerFactoryBean entity = new LocalContainerEntityManagerFactoryBean();
    entity.setPackagesToScan("org.mitre");
    entity.setPersistenceProviderClass(PersistenceProvider.class);
    entity.setDataSource(iamDataSource());
    entity.setJpaVendorAdapter(jpaAdapter());
    entity.setJpaPropertyMap(jpaProperties);
    entity.setPersistenceUnitName("defaultPersistenceUnit");

    return (EntityManagerFactory) entity;
  }

  // crypto-config.xml
  @Bean
  public JWKSetKeyStore defaultKeyStore() {

    Resource location = new FileSystemResource("keystore.jwks");
    JWKSetKeyStore keyStore = new JWKSetKeyStore();
    keyStore.setLocation(location);

    return keyStore;
  }

  @Bean
  public DefaultJWTSigningAndValidationService defaultSignerService()
    throws Exception {

    DefaultJWTSigningAndValidationService signerService = null;

    signerService = new DefaultJWTSigningAndValidationService(
      defaultKeyStore());
    signerService.setDefaultSignerKeyId("rsa1");
    signerService.setDefaultSigningAlgorithmName("RS256");

    return signerService;
  }

  @Bean
  public DefaultJWTEncryptionAndDecryptionService defaultEncryptionService()
    throws Exception {

    DefaultJWTEncryptionAndDecryptionService encryptionService = null;
    encryptionService = new DefaultJWTEncryptionAndDecryptionService(
      defaultKeyStore());
    encryptionService.setDefaultAlgorithm(JWEAlgorithm.RSA1_5);
    encryptionService.setDefaultDecryptionKeyId("rsa1");
    encryptionService.setDefaultEncryptionKeyId("rsa1");

    return encryptionService;
  }

  // task-config.xml

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredTokens() {

    tokenService().clearExpiredTokens();
  }

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredSites() {

    siteService().clearExpiredSites();
  }

  @Scheduled(fixedDelay = 300000, initialDelay = 600000)
  public void clearExpiredAuthzCodes() {

    codeService().clearExpiredAuthorizationCodes();
  }

  // local-config.xml

}
