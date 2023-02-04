# spring-authorization-server-pr-1056

## scenario
1. boot Run

```
$ ./gradlew bootRun
```

3. Issue a token with an already registered client

```
$ curl -X POST "http://localhost:8080/oauth2/token" -H 'Content-Type: application/x-www-form-urlencoded' -u messaging-client:secret -d "grant_type=client_credentials&scope=client.create"
```

3. Execute the following command using the displayed access_token

```
$ curl -X POST -v "http://localhost:8080/connect/register" -d '{ "client_name": "123", "redirect_uris": "http://127.0.0.1/callback", "grant_types": ["authorization_code", "client_credentials"] }' -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer (Set access_token here)'
```

4. Issue a token using the displayed client_id and client_secret

```
$ curl -X POST "http://localhost:8080/oauth2/token" -H 'Content-Type: application/x-www-form-urlencoded' -d "grant_type=client_credentials" \
  -u '(here client_id set):(here client_secret set)' 
```

---
displayed error

```
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
	at org.springframework.security.crypto.password.DelegatingPasswordEncoder$UnmappedIdPasswordEncoder.matches(DelegatingPasswordEncoder.java:289) ~[spring-security-crypto-6.0.1.jar:6.0.1]
	at org.springframework.security.crypto.password.DelegatingPasswordEncoder.matches(DelegatingPasswordEncoder.java:237) ~[spring-security-crypto-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider.authenticate(ClientSecretAuthenticationProvider.java:116) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.security.authentication.ProviderManager.authenticate(ProviderManager.java:182) ~[spring-security-core-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter.doFilterInternal(OAuth2ClientAuthenticationFilter.java:122) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter.doFilterInternal(NimbusJwkSetEndpointFilter.java:85) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter.doFilterInternal(OidcProviderConfigurationEndpointFilter.java:86) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.doFilterInternal(OAuth2AuthorizationEndpointFilter.java:156) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter.doFilterInternal(OAuth2AuthorizationServerMetadataEndpointFilter.java:84) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:107) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:93) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.csrf.CsrfFilter.doFilterInternal(CsrfFilter.java:116) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.header.HeaderWriterFilter.doHeadersAfter(HeaderWriterFilter.java:90) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.header.HeaderWriterFilter.doFilterInternal(HeaderWriterFilter.java:75) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.AuthorizationServerContextFilter.doFilterInternal(AuthorizationServerContextFilter.java:61) ~[spring-security-oauth2-authorization-server-1.0.0.jar:1.0.0]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.context.SecurityContextHolderFilter.doFilter(SecurityContextHolderFilter.java:82) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.context.SecurityContextHolderFilter.doFilter(SecurityContextHolderFilter.java:69) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter.doFilterInternal(WebAsyncManagerIntegrationFilter.java:62) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.session.DisableEncodeUrlFilter.doFilterInternal(DisableEncodeUrlFilter.java:42) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:374) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.FilterChainProxy.doFilterInternal(FilterChainProxy.java:233) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.security.web.FilterChainProxy.doFilter(FilterChainProxy.java:191) ~[spring-security-web-6.0.1.jar:6.0.1]
	at org.springframework.web.filter.DelegatingFilterProxy.invokeDelegate(DelegatingFilterProxy.java:351) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.web.filter.DelegatingFilterProxy.doFilter(DelegatingFilterProxy.java:267) ~[spring-web-6.0.4.jar:6.0.4]
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:185) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:158) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.springframework.web.filter.RequestContextFilter.doFilterInternal(RequestContextFilter.java:100) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:185) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:158) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.springframework.web.filter.FormContentFilter.doFilterInternal(FormContentFilter.java:93) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:185) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:158) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.springframework.web.filter.CharacterEncodingFilter.doFilterInternal(CharacterEncodingFilter.java:201) ~[spring-web-6.0.4.jar:6.0.4]
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116) ~[spring-web-6.0.4.jar:6.0.4]
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:185) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:158) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:177) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:97) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:542) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:119) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:92) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:78) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:357) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:400) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:65) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:859) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1734) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:52) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1191) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:659) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61) ~[tomcat-embed-core-10.1.5.jar:10.1.5]
	at java.base/java.lang.Thread.run(Thread.java:833) ~[na:na]
```
