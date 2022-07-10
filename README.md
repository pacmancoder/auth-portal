# auth_portal
Simple auth portal for protecting services, not supporting authentication (e.g. via ngnix's `auth_request`)

# auth-portal setup (docker-compose + nginx)
Let's saw we want to use [TiddlyWiki](https://tiddlywiki.com/) on our domain under `/tiddly` subpath
and allow internet access for it, but our resource (TiddlyWiki) supports only no-so-secure basic
authentication via login password, and we want robust authentication without storing plain passwords
in browser, and maybe even we want TOTP. And that's exact problem which is solved by `auth-portal`.

Let's see how we can do it with `nginx's` *auth_request* API and `docker-compose`.

1. Create empty directory which will be used as docker data volume (In this
    example: `/home/user/auth-portal`)
1. Init auth portal:
    ```sh
    docker run -v /home/user/auth-portal:/data pacmancoder/auth-portal init
    ```
    Also, session TTL could be set on this step via adding `--session-ttl=<value in seconds>`
    to the command
1. Add user for `tiddly` service:
    ```sh
    docker run -v /home/user/auth-portal:/data -it pacmancoder/auth-portal \
        set-credentials --login user --service tiddly --enable-totp
    ```
    After that you will be asked to enter password(without echo), and QR code for TOTP will be
    displayed  (which could be used in your favourite 2FA authentication app)
1. configure nginx to run, here is example server configuration (conf.d/static.conf):
    ```nginx
    server {
        listen 443 ssl;
        server_name 'sub.domain.com';

        absolute_redirect off;

        ssl_certificate /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;

        location / {
            deny all;
        }

        location /wiki/ {
            resolver 127.0.0.11; # Docker DNS
            auth_request /auth-portal/auth/wiki/;
            # Redirect unauthorized users to login page
            error_page 401 /auth-portal/login/wiki/;
            proxy_pass http://tiddlywiki:8080;
        }

        location /auth-portal/ {
            resolver 127.0.0.11;
            proxy_pass http://auth-portal:8080;
        }

        # Required to make POST/PUT/etc. requests with body work
        location = /auth-portal/auth/wiki/ {
            internal;
            resolver 127.0.0.11;
            proxy_pass http://auth-portal:8080;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }
    }
    ```
1. Set docker-compose config
    ```yml
    version: "3.9"
    services:
    nginx:
        image: nginx:1.21
        volumes:
        - ./data/nginx/static:/etc/nginx/html:ro
        - ./data/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
        - ./data/nginx/conf.d:/etc/nginx/conf.d:ro
        - ./data/certs:/etc/nginx/certs:ro
        ports:
        - 443:443/tcp
        depends_on:
        - tiddlywiki
        restart: unless-stopped
    tiddlywiki:
      image: nicolaw/tiddlywiki:5.2.2
      volumes:
        - ./data/tiddlywiki:/var/lib/tiddlywiki
      restart: unless-stopped
      environment:
        - TW_WIKINAME=wiki
        - TW_PORT=8080
        # Also, in case of TiddlyWiki you need to set `$:/config/tiddlyweb/host` tiddler to
        # full path to your wiki e.g.: `https://mydomain.com/wiki/`
        - TW_PATHPREFIX=/wiki
    auth-portal:
      image: pacmancoder/auth-portal:0.1
      volumes:
        -./data/auth-portal:/data
      restart: unless-stopped
      environment:
        - AP_SERVE_PREFIX=/auth-portal
        # Following variable could be set to allow auth portal to run over insecure http
        # (uses non-secure cookies, recommended only for testing)
        # - AP_ALLOW_HTTP=true
   ```
1. You are good to go, visit `/wiki`, login with your credentials and enjoy your protected resource!
