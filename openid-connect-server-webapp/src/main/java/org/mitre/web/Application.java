package org.mitre.web;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

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

    return application.sources(Application.class);
  }

  @Bean(destroyMethod = "shutdown")
  public Executor taskScheduler(
    final @Value("${server.scheduler-pool-size:10}") int scheduledThreadPoolSize) {

    return Executors.newScheduledThreadPool(scheduledThreadPoolSize);
  }

}
