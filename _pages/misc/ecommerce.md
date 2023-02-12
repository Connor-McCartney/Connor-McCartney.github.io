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
