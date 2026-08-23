/**
 * VULNERABLE TEST APP — FOR SCANNER TESTING ONLY
 * ------------------------------------------------
 * This app contains INTENTIONAL security bugs so you can practice using
 * tools like Snyk, OWASP ZAP, or npm audit and see what they catch.
 *
 * DO NOT:
 *  - deploy this to a public server
 *  - copy these patterns into a real client project
 *  - use these fake secrets/passwords anywhere real
 *
 * Each vulnerability below is labeled with [VULN-N] and a short note on
 * what's wrong and how it would normally be fixed.
 */

const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// [VULN-1] Hardcoded secret key committed to source code.
// Fix: load from process.env.JWT_SECRET, keep real value only in .env (gitignored).
const JWT_SECRET = "super-secret-key-12345";

// [VULN-2] Hardcoded database credentials / API key left in code.
// Fix: same as above — environment variables, never in source.
const STRIPE_API_KEY = "sk_test_FAKEKEY1234567890EXAMPLE";

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)");
  // [VULN-3] Passwords hashed with MD5 — fast, unsalted, easily cracked.
  // Fix: use bcrypt or argon2 with a per-user salt.
  const weakHash = crypto.createHash("md5").update("password123").digest("hex");
  db.run("INSERT INTO users (email, password) VALUES (?, ?)", ["demo@test.com", weakHash]);
});

app.get("/", (req, res) => {
  res.send(`
    <h1>Vulnerable Test App</h1>
    <p>Endpoints to try:</p>
    <ul>
      <li>GET /search?term=test — SQL injection</li>
      <li>GET /greet?name=World — reflected XSS</li>
      <li>POST /login — weak auth / hardcoded JWT secret</li>
      <li>GET /profile/1 — broken access control (IDOR)</li>
    </ul>
  `);
});

// [VULN-4] SQL Injection — user input concatenated directly into the query.
// Try: /search?term=' OR '1'='1
// Fix: use parameterized queries — db.all("...WHERE email LIKE ?", [`%${term}%`])
app.get("/search", (req, res) => {
  const term = req.query.term || "";
  const query = `SELECT * FROM users WHERE email LIKE '%${term}%'`;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).send("DB error: " + err.message);
    res.json(rows);
  });
});

// [VULN-5] Reflected XSS — user input echoed into HTML without escaping.
// Try: /greet?name=<script>alert(1)</script>
// Fix: escape output (e.g. with a templating engine's auto-escaping, or a
// library like `escape-html`) instead of building HTML with raw strings.
app.get("/greet", (req, res) => {
  const name = req.query.name || "stranger";
  res.send(`<h2>Hello, ${name}!</h2>`);
});

// [VULN-6] Broken authentication — weak hashing + no rate limiting on login.
// Fix: bcrypt.compare(), add rate limiting / account lockout, use HTTPS-only
// secure cookies for sessions.
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash("md5").update(password || "").digest("hex");

  db.get("SELECT * FROM users WHERE email = ? AND password = ?", [email, hash], (err, user) => {
    if (err) return res.status(500).send("DB error");
    if (!user) return res.status(401).send("Invalid credentials");

    // Token signed with the hardcoded secret from VULN-1
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);

    // [VULN-7] Cookie missing Secure, HttpOnly, and SameSite flags.
    // Fix: res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "strict" })
    res.cookie("token", token);
    res.send("Logged in");
  });
});

// [VULN-8] Broken Access Control / IDOR — no check that the requester
// actually owns this profile, or is even logged in at all.
// Fix: verify the JWT from the request, then confirm req.user.id === id
// before returning data.
app.get("/profile/:id", (req, res) => {
  const id = req.params.id;
  db.get("SELECT id, email FROM users WHERE id = ?", [id], (err, user) => {
    if (err) return res.status(500).send("DB error");
    res.json(user || {});
  });
});

// [VULN-9] Verbose error handling leaks stack traces to the client.
// Fix: log the full error server-side only; send a generic message to users.
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable test app running on http://localhost:${PORT}`);
  console.log("Remember: local testing only, never expose this publicly.");
});
