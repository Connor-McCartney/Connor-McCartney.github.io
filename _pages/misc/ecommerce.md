Reference:
<https://www.youtube.com/watch?v=GarMdDTAZJo>

# Technologies
- NextJS
- Cloudflare
- Google Domains
- Stripe
- Nginx Proxy Manager

# Port forwarding (80 and 443)

I go to to 192.168.0.1

I have an Optus router, in the gui I go to:
Network Settings > 
Port Forwarding > 
Add rules Manually > 

Service: http or https
Protocol: TCP
Internal host: your local machine ip
External host: leave blank

# Boilerplate test

```html
<html>  
    <body>  
        <h1>Test!</h1>   
    </body>  
</html>
```

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
