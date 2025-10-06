# Bounce.pkt

This app allows you to http-forward a PKT domain.

1. `CNAME bounce.pkt`
2. `TXT BOUNCE=https://domain.of.your.website`
3. Go to bounce.pkt
4. Enter your domain name and check it
5. enter http://your.domain.pkt.tld and you'll be redirected

## Configuration

Default nginx route to bounce server:

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:10000;
        proxy_set_header Host $host;
    }
}
```

Admin nginx conf:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    include /etc/pkt-cert/bounce.pkt.nginx.inc;
    ssl_dhparam /etc/nginx/dhparam.pem;
    ssl_protocols TLSv1.2;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
    ssl_ecdh_curve secp384r1;

    root /home/user/bounce-pkt/www;
    index index.html;

    access_log /var/log/nginx/bounce_access.log;
    error_log /var/log/nginx/bounce_error.log;

    location /api/v1 {
        proxy_pass http://127.0.0.1:10001;
    }
    location / {
        try_files $uri $uri/ =404;
    }

    error_page 404 /404.html;
    location = /404.html {
        internal;
    }
}
```

## License

MIT OR Apache 2