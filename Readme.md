## Self-Hosted URL Shortener

This project is a **self-hosted URL shortener service** similar to **Cutt.ly** or **Bitly**, but fully under your control.
You can create short URLs through a single API endpoint, making it easy to integrate into existing scripts or applications.

---

## ✨ Features

- [X] Self-hosted — you own the data
- [X] Uses MySQL for persistent storage
- [X] Single-file Node.js server
- [X] Open Query-based API Standard
- [X] Supports custom aliases (via `name` parameter)
- [X] Fast redirect routing
- [X] Easy to deploy on VPS or Docker
- [X] Extendable (analytics, auth, expiring links, etc.)

---

## 🛠️ Tech Stack

| Component | Technology                 |
| --------- | -------------------------- |
| Backend   | Node.js + Express          |
| Database  | MySQL                      |
| Utils     | Lodash                     |
| Extras    | Axios (optional URL check) |

---

## Installation

### Clone & Install

```bash
git clone <your-repo-url>
cd url-shortener
npm install
```

### Database Setup

Create the database:

```sql
CREATE DATABASE urlshortener;
```

The service will automatically create the `urls` table on startup.

### Configure DB Credentials

Update the MySQL settings in the code if required:

```js
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "urlshortener"
});
```

### Run Server

```bash
node server.js
```

Server will start at:

```
http://localhost:3000
```

---

## API Usage

### Endpoint Format

```
GET /api/generate?key={key}&source={longUrl}&useHeader=1&name={customAlias}
```

| Param        | Description                                  | Required |
| ------------ | -------------------------------------------- | -------- |
| `key`        | API key (depending on config)                | ✅        |
| `source`     | The original long URL to be shortened        | ✅        |
| `useHeader`  | Static param for API compatibility (use `1`) | ❌        |
| `name`       | Custom short alias (e.g. "my-link")          | ❌        |
| `onetimeUse` | Allows generating one time use links         | ❌        |

### Example Request

```
http://localhost:3000/api/generate?key=12345&source=https://example.com&useHeader=1&name=myalias
```

### Example Response

```json
{
  "status": "ok",
  "shortUrl": "http://localhost:3000/myalias",
  "originalUrl": "https://example.com"
}
```

Then accessing:

```
http://localhost:3000/myalias
```

will redirect to:

```
https://example.com
```

---

## 🔐 Security Notes

* Use HTTPS via reverse proxy (Nginx / Traefik)


Thank you,
SmartinfoLogiks Team