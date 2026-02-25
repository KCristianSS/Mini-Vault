import express from "express";
import { createServer as createViteServer } from "vite";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import db from "./src/db.ts";
import { encrypt, decrypt } from "./src/cryptoUtils.ts";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "default_encryption_key_32_chars_!!";

app.use(express.json());

// Middleware to verify JWT
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- Auth Routes ---
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)");
    const info = stmt.run(email, hashedPassword);
    res.status(201).json({ id: info.lastInsertRowid });
  } catch (error: any) {
    if (error.code === 'SQLITE_CONSTRAINT') {
      res.status(400).json({ error: "Email already exists" });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user: any = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (user && await bcrypt.compare(password, user.password_hash)) {
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// --- Credential Routes ---
app.get("/api/credentials", authenticateToken, (req: any, res) => {
  const credentials = db.prepare(`
    SELECT id, service_name, account_username, url, notes, created_at, updated_at 
    FROM credentials 
    WHERE user_id = ?
  `).all(req.user.id);
  res.json(credentials);
});

app.post("/api/credentials", authenticateToken, (req: any, res) => {
  const { serviceName, accountUsername, password, url, notes } = req.body;
  if (!serviceName || !password) return res.status(400).json({ error: "Service name and password required" });

  const encryptedPassword = encrypt(password, ENCRYPTION_KEY);
  const stmt = db.prepare(`
    INSERT INTO credentials (user_id, service_name, account_username, password_encrypted, url, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(req.user.id, serviceName, accountUsername, encryptedPassword, url, notes);
  res.status(201).json({ id: info.lastInsertRowid });
});

app.get("/api/credentials/:id", authenticateToken, (req: any, res) => {
  const { id } = req.params;
  const { reveal } = req.query;
  
  const credential: any = db.prepare("SELECT * FROM credentials WHERE id = ? AND user_id = ?").get(id, req.user.id);

  if (!credential) return res.status(404).json({ error: "Credential not found" });

  const response: any = {
    id: credential.id,
    service_name: credential.service_name,
    account_username: credential.account_username,
    url: credential.url,
    notes: credential.notes,
    created_at: credential.created_at,
    updated_at: credential.updated_at
  };

  if (reveal === 'true') {
    response.password = decrypt(credential.password_encrypted, ENCRYPTION_KEY);
    
    // Audit log
    db.prepare("INSERT INTO audit_logs (user_id, credential_id, action, metadata) VALUES (?, ?, ?, ?)")
      .run(req.user.id, id, 'SHOW_PASSWORD', JSON.stringify({
        ip: req.ip,
        userAgent: req.get('user-agent')
      }));
  }

  res.json(response);
});

app.put("/api/credentials/:id", authenticateToken, (req: any, res) => {
  const { id } = req.params;
  const { serviceName, accountUsername, password, url, notes } = req.body;

  const credential: any = db.prepare("SELECT id FROM credentials WHERE id = ? AND user_id = ?").get(id, req.user.id);
  if (!credential) return res.status(404).json({ error: "Credential not found" });

  let query = "UPDATE credentials SET service_name = ?, account_username = ?, url = ?, notes = ?, updated_at = CURRENT_TIMESTAMP";
  const params = [serviceName, accountUsername, url, notes];

  if (password) {
    query += ", password_encrypted = ?";
    params.push(encrypt(password, ENCRYPTION_KEY));
  }

  query += " WHERE id = ?";
  params.push(id);

  db.prepare(query).run(...params);
  res.json({ success: true });
});

app.delete("/api/credentials/:id", authenticateToken, (req: any, res) => {
  const { id } = req.params;
  const result = db.prepare("DELETE FROM credentials WHERE id = ? AND user_id = ?").run(id, req.user.id);
  
  if (result.changes === 0) return res.status(404).json({ error: "Credential not found" });
  res.json({ success: true });
});

// --- Audit Logs ---
app.get("/api/audit", authenticateToken, (req: any, res) => {
  const logs = db.prepare(`
    SELECT a.*, c.service_name 
    FROM audit_logs a
    JOIN credentials c ON a.credential_id = c.id
    WHERE a.user_id = ?
    ORDER BY a.created_at DESC
  `).all(req.user.id);
  res.json(logs);
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
