# Abandoned but Not Forgotten: server version

Requires Node 22+ (no npm packages needed).

    node server.js                      # http://localhost:3000
    PORT=8080 COOKIE_SECURE=1 node server.js   # behind HTTPS
    DB_PATH=/var/lib/abnf/abnf.db node server.js

Accounts and progress are stored in a SQLite file (default `data/abnf.db`).
Keep `index.html` and `server.js` together; open the game through the server URL, not the file.
