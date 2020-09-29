Jenkins和db.migration注意点：

以order-service

为例：

1.在写测试时候，测试类的注解如下，会有一个自定义的注解，意思是用测试环境进行测试。

![image-20200929162945683](https://i.loli.net/2020/09/29/asMh2WywoR5VjNZ.png)

![image-20200929163007689](https://i.loli.net/2020/09/29/Z5Gz4XtdpTnjLl2.png)

再次提醒：测试环境是在一个h2数据库(一个内存数据库)，并不会反应在本地数据库中。

2.目前db.migratiopn如下，如果需要数据库有测试数据，请不要用这种方式进行Insert数据，可以直接操作数据库。

如果存在一个init sattus的.sql文件，请注意删除。

![image-20200929163105668](https://i.loli.net/2020/09/29/nPgOehWTIpc8A9Q.png)



3.由于删除了以前我自己写的一个init sattus文件，所以以后我们的order_status表中数据需要我们代码里去保证。

这边我们可以使用先存储OrderStatus到数据库，然后再存储Order的方式，防止Status在数据库中还未存在而报错。(其他操作也需要注意这一点)![image-20200929163452076](https://i.loli.net/2020/09/29/LtqNlmkJYH6aSez.png)



4.测试中需要保证下图这个文件的存在(他本来是存在的，以前被我删除过，如果你是参考过我的测试代码请注意这一点。在Jenkins上运行需要保证所有测试都能通过，请提前测试完成)

![image-20200929163945178](https://i.loli.net/2020/09/29/PLUyQBYjnVCmueo.png)

5.如果控制台出现 CREATE SCHEMA IF NOT EXISTS "public"，可以尝试下载这个public前后加上""，（不一定有用）。

![image-20200929163157132](https://i.loli.net/2020/09/29/En3hReNWSYcOuQG.png)