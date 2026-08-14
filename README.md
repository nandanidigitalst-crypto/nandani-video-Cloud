# Nandani Wedding Cloud

Secure wedding photo/video cloud with separate **Admin** and **Customer** accounts.

## Included
- Admin login with secure password hashing (Node `scrypt`)
- Customer creation/deactivation from Admin Dashboard
- Customer username/password login
- Admin can create and assign wedding albums to customers
- Customers can only see their own albums
- Photo and long-video upload with 8 MB chunks
- 20 GB application-level single-file limit
- Online playback, download and delete
- Persistent filesystem storage via `STORAGE_ROOT`
- HTTP-only session cookie

## Admin credentials
Do **not** put the admin password in GitHub. Set these environment variables on Railway/your server:

`ADMIN_USERNAME=your-admin-username`
`ADMIN_PASSWORD=your-strong-password`

On first start, the application creates the admin account if it does not already exist.

## Local run
Node.js 18+:
1. `npm install`
2. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in your shell/environment.
3. `npm start`
4. Open `http://localhost:3000`

Default local storage: `./storage/`.

## Railway
Deploy from GitHub, then add environment variables:
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `STORAGE_ROOT=/app/storage`

Add a Railway Volume mounted at `/app/storage` so customer accounts, album metadata and uploaded files survive redeploys. For very large libraries, S3-compatible object storage is recommended.

## Security notes
Use HTTPS in production. The application stores password hashes, not plaintext passwords. Customer media endpoints require an authenticated session and check album ownership.