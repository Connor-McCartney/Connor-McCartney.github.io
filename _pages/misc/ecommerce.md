Reference:
<https://www.youtube.com/watch?v=bG88qVHGGic>

# Technologies
- NextJS
- Nginx
- Stripe


# Port forwarding (80 and 443)

I go to to 192.168.0.1

I have an Optus router, in the gui I go to: <br>
Network Settings >  Port Forwarding > Add rules Manually

Service: http or https <br>
Protocol: TCP <br>
Internal host: your local machine ip <br>
External host: leave blank <br>

# Boilerplate test

Create next project:

```
npx create-next-app
```

Build and run:

```
cd test
npx next build
sudo chown root .
sudo npx next start -p 80
```

Then visit your public IP and it should be visible

Now try this and you should see an SSL error because we haven't implemented this yet. 

```
sudo npx next start -p 443
```

# Nginx

Running the website directly on port 80 opens you up to hackers. 

Use nginx reverse proxy to cirumvent this. 

Start it with `sudo systemctl start nginx` and you should be able to see the default page if you go to your public IP.

Then run your website on some other random port, eg `sudo npx next start -p 3000`

Now edit /etc/nginx/nginx.conf

```bash
...
    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            proxy_pass http://127.0.0.1:3000;
            #root   /usr/share/nginx/html;
            #index  index.html index.htm;
        }
...
```

Apply the changes with `sudo systemctl restart nginx`


# Domain + SSL

There are lots of sites to buy domains, I used <https://porkbun.com>

<https://kb.porkbun.com/article/70-how-to-turn-off-auto-renew>

<https://kb.porkbun.com/article/71-how-your-free-ssl-certificate-works>

Edit DNS records, delete the existing ones and add:

Type: `A-Address record` <br>
Host: `example.com` <br>
Answer (public IP): `xx.xx.xx.xx`

<br>

Don't expect immediate results, it can take some time. 


```
sudo mkdir /etc/pki
sudo mkdir /etc/pki/nginx
sudo cp domain.cert.pem /etc/pki/nginx/server.crt
sudo mkdir /etc/pki/nginx/private
sudo cp private.key.pem /etc/pki/nginx/private/server.key
```

Edit nginx.cong again:

```bash
    #HTTPS server
    
    server {
        listen       443 ssl;
        server_name  localhost;

        ssl_certificate      "/etc/pki/nginx/server.crt";
        ssl_certificate_key  "/etc/pki/nginx/private/server.key";

        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        location / {
            proxy_pass http://127.0.0.1:3000;
            #root   html;
            #index  index.html index.htm;
        }
```
