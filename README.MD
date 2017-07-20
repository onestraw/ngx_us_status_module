ngx_us_status_module
===
Nginx upstream status module is used to fetch basic information of upstream at runtime,
and can be integrated with http/stream health check module.

Example
----

- ./configure --add-module=/path/to/ngx_us_status_module --prefix=`pwd`/nginx-install --with-stream
- boot with [test_nginx.conf](test_nginx.conf)
- run the following commands


root@~/# curl "http://127.0.0.1:8080/us_status?type=stream&upstream=stream_pool_1"

    [non-backup]number,total_weight
    2,2
    
    server,weight,max_fails,fail_timeout,backup,down,status
    127.0.0.1:7000,1,1,10,0,0,-1
    127.0.0.1:7001,1,1,10,0,1,0
    127.0.0.1:7002,1,1,10,1,0,0
    
    
root@~/# curl "http://127.0.0.1:8080/us_status?type=http&upstream=http_pool_1"

    [non-backup]number,total_weight
    3,3
    
    server,weight,max_fails,fail_timeout,backup,down,status
    127.0.0.1:9000,1,1,10,0,0,-1
    127.0.0.1:9001,1,1,10,0,0,-1
    127.0.0.1:9003,1,1,10,0,1,0
    127.0.0.1:9002,1,1,10,1,0,0

