### 1.webapi-getway中Spring Security的配置文件简单介绍

![image-20201014163939939](https://i.loli.net/2020/10/14/sPyimrO56YX8Mtp.png)





最后一行表示Spring Security永远不会创建HttpSession，它不会使用HttpSession来获取SecurityContext

在此方法之上还有一个重载方法，区别如下：

>#### configure（HttpSecurity）
>
>允许基于选择匹配在资源级别配置基于Web的安全性-例如，以下示例将以/ admin /开头的URL限制为具有ADMIN角色的用户，并声明需要使用其他任何URL成功认证。
>
>```java
>protected void configure(HttpSecurity http) throws Exception {
>    http
>        .authorizeRequests()
>        .antMatchers("/admin/**").hasRole("ADMIN")
>        .anyRequest().authenticated()
>}
>```
>
>#### configure（WebSecurity）
>
>用于影响全局安全性的配置设置（忽略资源，设置调试模式，通过实现自定义防火墙定义拒绝请求）。例如，以下方法将导致以/ resources /开头的任何请求都被忽略，以进行身份验证。
>
>```java
>public void configure(WebSecurity web) throws Exception {
>    web
>        .ignoring()
>        .antMatchers("/resources/**");
>}
>```
>
>参考链接：
>
>https://www.jianshu.com/p/d3f4657ff3fa
>
>**重要补充：**
>
>虽然这两个都是继承WebSecurityConfigurerAdapter后重写的方法，但是**http.permitAll**不会绕开springsecurity的过滤器验证，相当于只是**允许该路径通过过滤器**，而**web.ignoring**是直接**绕开**spring security的**所有filter**，**直接跳过验证**。



#### 1.1AuthenticationFilter



![image-20201014164232185](https://i.loli.net/2020/10/14/1xQVKNuEcJhWpC3.png)

#### 1.2PlatformAuthenticationFilter

![image-20201014164451318](https://i.loli.net/2020/10/14/GHmvUgMLSXq5kOf.png)



#### 1.3AuthorizationFilter

以下介绍的方法来自 Webapi-getway的fun.hercules.webapi.security.AuthorizationFilter

除了我们上文提到过的permitAll的请求url，其他url都会到这一步进行doFilterInternal，用来判断token的正确性，判断正确之后才会去转发并执行到我们真正的Controller

```java
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(HEADER_STRING);

        //如果header为null或者Authorization的value不是以Bearer 开头
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String token = request.getHeader(HEADER_STRING);
            if (token != null) {

                Claims body = null;
                try {
                    //校验Token
                    body = Jwts.parser()
                            .setSigningKey(SECRET.getBytes(Charset.defaultCharset()))
                            .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                            .getBody();
                } catch (ExpiredJwtException e) {
                    throw new UserAuthenticationException(ErrorCode.TOKEN_EXPIRED);
                }
                //通过token拿到userId
                String userId = String.valueOf(body.get("userId"));
                User user;

                try {
                    //去UserService的DB里查找有没有对应的user
                    user = userClient.getUserById(userId);
                } catch (Exception e) {
                    throw new UserAuthenticationException(ErrorCode.INVALID_USER);
                }

                //校验user的status
                if (!user.getStatus().equals("ENABLED")) {
                    throw new UserAuthenticationException(ErrorCode.DISABLED_STATUS);
                }

                //把user封装到UsernamePasswordAuthenticationToken对象中，再赋给authentication
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                authenticationToken.setDetails(user);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);


                Map<String, Object> claims = body.entrySet().stream()
                        .filter(entry -> forwardKeys.contains(entry.getKey()))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
                claims.put("userName", user.getUsername());
                //刷新Token的持续时长
                String refreshedToken = Jwts.builder()
                        .setClaims(claims)
                        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                        .signWith(SignatureAlgorithm.HS512, SECRET.getBytes(Charset.defaultCharset()))
                        .compact();

                // header must add to zuul request header
                RequestContext.getCurrentContext().addZuulRequestHeader(HEADER_STRING, TOKEN_PREFIX + refreshedToken);
                response.addHeader(HEADER_STRING, TOKEN_PREFIX + refreshedToken);
            }
            chain.doFilter(request, response);
        } catch (UserAuthenticationException ex) {
            // skip chain and return 401
            onUnsuccessfulAuthentication(request, response, ex);
        }
    }
```

通过上面这些方法来配置权限并校验Token，在各自的项目中，比如UserService中也有过滤器，主要是为了获得user的role，用来判断当前的user是否有权限调用对应的方法。

### 2.用户、角色与权限的交互



> 用户：主要包含用户名，密码和当前用户的角色信息，可实现认证操作。
>
> 角色：主要包含角色名称，角色描述和当前角色拥有的权限信息，可实现授权操作。
>
> 权限：权限也可以称为菜单，主要包含当前权限名称，url地址等信息，可实现动态展示菜单。
>
> 注：这三个对象中，用户与角色是多对多的关系，角色与权限是多对多的关系，用户与权限没有直接关系，二者是通过角色来建立关联关系的。

#### 2.1角色在方法中的应用：OperationLogService

以下方法来自OrderService的 fun.hercules.order.order.platform.order.service.OperationLogService

表示当前用户需要拥有对应的权限角色才能调用这个方法。

![image-20201014203755276](https://i.loli.net/2020/10/14/i7bKCS9zjM6oOcy.png)

对应的角色在数据库中的值：我们现在登录的twuser对应的role_id正是3，也就是PlatformAdmin

![image-20201014210220037](https://i.loli.net/2020/10/14/scpLnKYv4WrkXDd.png)

![image-20201014203654034](https://i.loli.net/2020/10/14/styrHEBJFacXfl5.png)



#### 2.2那么Spring Security是什么时候获得这个角色的呢？

答案在OrderService本地自定义的filter。

![image-20201014205144416](https://i.loli.net/2020/10/14/JIzKyuAehYRLdGZ.png)

可以看到，在这个自定义的filter中，将传过来的user中的信息，其中就包括用户的角色，放到了SecurityContext中。

SecurityContext中存储了当前用户的认证以及权限信息，从Context中我们也可以大概猜到，他是一个上下文的变量。

![image-20201014205112275](https://i.loli.net/2020/10/14/e6nTOsLVMIwm4xN.png)

至此，我们Spring Security的简单介绍就到此结束。



再加个餐，下面这篇文章对JWT是我见过写的最好的了,也解决了我不少疑问。

[理解 JWT 的使用场景和优劣](https://www.cnkirito.moe/jwt-learn-3/)