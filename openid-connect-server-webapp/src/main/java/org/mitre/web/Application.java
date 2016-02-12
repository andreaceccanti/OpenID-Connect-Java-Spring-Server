package org.mitre.web;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.mitre.web.config.IamAuthorizationServer;
import org.mitre.web.config.IamConfig;
import org.mitre.web.config.IamResourceServer;
import org.mitre.web.config.JpaConfig;
import org.mitre.web.config.MvcConfig;
import org.mitre.web.config.SchedulingConfig;
import org.mitre.web.config.WebSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
@ComponentScan(basePackages = { "org.mitre" })
@PropertySource("classpath:application.yml")
public class Application extends SpringBootServletInitializer {

  public static void main(final String[] args) {

    SpringApplication.run(Application.class, args);

  }

  @Override
  protected SpringApplicationBuilder configure(
    final SpringApplicationBuilder application) {

    application.sources(Application.class, IamConfig.class,
      IamAuthorizationServer.class, IamResourceServer.class, JpaConfig.class,
      MvcConfig.class, SchedulingConfig.class, WebSecurityConfig.class);
    return application;
  }

  @Bean(destroyMethod = "shutdown")
  public Executor taskScheduler(
    final @Value("${server.scheduler-pool-size:10}") int scheduledThreadPoolSize) {

    return Executors.newScheduledThreadPool(scheduledThreadPoolSize);
  }

}
