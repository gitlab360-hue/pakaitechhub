# PAK AI TechHub — website + live admin panel

Ek chhota Node.js server jo website serve karta hai, admin ki changes **foran live** save karta hai
(koi file dobara upload nahi karni), images/audio upload leta hai aur contact-form leads save + email karta hai.
Koi database ya API key nahi chahiye. Node 18+ chahiye.

## Chalane ka tareeqa

```bash
node server.js            # ya: npm start
```

Pehli baar chalane par console mein **admin password** print hota hai. Apna password khud set karna ho to:

```bash
ADMIN_PASSWORD='koi-mazboot-password' node server.js
```

Phir `http://localhost:3000` kholein. Admin ke liye footer mein "Admin" dabayein (ya URL ke aakhir mein `#admin`).

## Admin se kya badal sakte hain

General (brand, logo, colours) · Hero (text + image) · Contact & WhatsApp · Section headings · Show/Hide sections ·
Services · Solutions (image + price + link) · Categories · How it works · Stats · Academy · About (image, team photos) ·
Provider banner · FAQ · Voice agent (greeting, jawab, awaz ki speed/pitch, recorded audio) · Leads · Settings.

"Save & Go Live" dabate hi har visitor ko changes nazar aate hain.

## WhatsApp aur Email

* **WhatsApp:** Admin → *Contact & WhatsApp* mein number likhein (`03001234567` ya `923001234567`). Floating button, hero button aur form ka "Send on WhatsApp" khud aa jate hain.
* **Email:** form har lead `data/leads.json` mein save karta hai (Admin → Leads mein dikhti hai). Email notification ke liye Admin → *Settings*:
  * **SMTP** (Gmail / Outlook / cPanel): pehle folder mein ek baar `npm install` chalayein, phir host/user/password daalein. Gmail ke liye *App password* use karein.
  * ya **Web3Forms** key (koi install nahi, web3forms.com par free).
  * "Send test email" se check kar lein.

## Voice agent ki awaz

Awaz browser ki apni TTS voices se aati hai. Site ab sab se natural voice khud chunti hai (Microsoft "Natural"/"Online", Google, Siri), jumlay jumlay karke bolti hai aur speed/pitch admin se set hoti hai.
Sab se behtar nateeja **Microsoft Edge** mein milta hai (free Natural voices). Bilkul studio-quality ke liye Admin → Voice agent mein har jawab ke saath apni **recorded audio** (MP3) upload kar dein — woh robot awaz ki jagah chalegi.

## Hosting (zaroori)

Server ko aisi jagah chalayein jahan **file disk save rahe**: VPS (DigitalOcean/Hetzner/Contabo) + `pm2`, Render/Railway/Fly (persistent disk/volume ke saath), ya cPanel "Setup Node.js App".
Vercel/Netlify jaisi serverless hosting par yeh save nahi hogi. Data folder alag rakhna ho: `DATA_DIR=/var/pakai-data node server.js`.

```bash
npm i -g pm2 && ADMIN_PASSWORD='...' pm2 start server.js --name pakai && pm2 save
```

HTTPS lagayein (Nginx/Caddy/Cloudflare) — mic (voice input) sirf HTTPS par chalta hai.

## Files

* `server.js` — server (auth, save, upload, leads, email)
* `public/index.html` — poori website + admin panel
* `data/` — site.json, uploads/, leads.json, backups/ (har save se pehle auto-backup, aakhri 30), secrets.json (**kisi ko share na karein**)

## Security notes

Password scrypt se hashed hai, login rate-limited hai, session cookie HttpOnly + SameSite=Strict hai, uploads sirf asli images/audio (file signature se check) allowed hain, aur form mein spam-honeypot hai.
