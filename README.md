# Secure Auth - Authentication & Session Management

## Overview
Secure Auth is a **framework-agnostic authentication system** for Node.js applications. It provides **secure user authentication, session management, and WebAuthn support**, all while remaining **database-agnostic**. 

### **Key Features**
- 🔒 **Secure Authentication** using **Argon2** password hashing and **Ed25519 JWT signing**
- 📌 **Session-Based JWTs**: Tokens tied to a **session ID stored in the database**
- 🛡 **Automatic Session Validation**: JWTs are valid only if the session exists in the DB
- 🌍 **Framework-Agnostic**: Works with Express, Fastify, Koa, or any other Node.js backend
- 🔑 **WebAuthn Passkey Support**
- 🚀 **No Direct Database Handling**: The developer provides session storage logic

---

## 📦 Installation
```sh
npm install @mikelambson/secure-auth
```

---

## 🔧 Setup & Configuration
### **1️⃣ Implement a `SessionStore` for Your Database**
Since Secure Auth does **not handle databases directly**, you need to implement a `SessionStore`.

### **🗄 Table Structure**
| Column Name  | Type                     | Description                          |
|-------------|-------------------------|--------------------------------------|
| `session_id`  | `VARCHAR(255) PRIMARY KEY` | Unique session identifier (UUID)     |
| `user_id`     | `VARCHAR(255) NOT NULL`  | References the user who owns the session |
| `created_at`  | `TIMESTAMP DEFAULT NOW()` | Timestamp when the session was created |
| `expires_at`  | `TIMESTAMP`              | Expiry time (optional, if enforcing expiration) |

### **Example Schema for Different Databases**

#### **PostgreSQL / MySQL**
```sql
CREATE TABLE sessions (
  session_id VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP
);
```

Example for **PostgreSQL (Knex.js)**:
```ts
import { SessionStore } from "@mikelambson/secure-auth";
import knex from "knex";

const db = knex({ client: "pg", connection: process.env.DATABASE_URL });

export class MySessionStore implements SessionStore {
  async saveSession(sessionId: string, userId: string): Promise<boolean> {
    await db("sessions").insert({ session_id: sessionId, user_id: userId });
    return true;
  }
  async isSessionValid(sessionId: string): Promise<boolean> {
    const session = await db("sessions").where({ session_id: sessionId }).first();
    return !!session;
  }
  async deleteSession(sessionId: string): Promise<boolean> {
    await db("sessions").where({ session_id: sessionId }).del();
    return true;
  }
}
```

Example for **Prisma ORM**:
```ts
import { SessionStore } from "@mikelambson/secure-auth";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export class PrismaSessionStore implements SessionStore {
  async saveSession(sessionId: string, userId: string): Promise<boolean> {
    await prisma.session.create({ data: { sessionId, userId } });
    return true;
  }
  async isSessionValid(sessionId: string): Promise<boolean> {
    const session = await prisma.session.findUnique({ where: { sessionId } });
    return !!session;
  }
  async deleteSession(sessionId: string): Promise<boolean> {
    await prisma.session.delete({ where: { sessionId } });
    return true;
  }
}
```

---

### **2️⃣ Initialize `AuthService`**
```ts
import { AuthService } from "@mikelambson/secure-auth";
import { readFileSync } from 'fs';
import { MySessionStore } from "./mySessionStore";

// Load your Ed25519 key pair (e.g., from .env or files)
const privateKey = readFileSync(process.env.JWT_PRIVATE_KEY!, 'utf8');
const publicKey = readFileSync(process.env.JWT_PUBLIC_KEY!, 'utf8');

// Optional: Pass a session store implementation (or null to bypass)
const sessionStore = new MySessionStore(); //from your created store constructor
const authService = new AuthService(privateKey, publicKey, sessionStore);
```

---

## 🚀 Authentication Methods
### **🔐 User Registration (Hash Passwords)**
```ts
const newUser = await authService.registerUser({
  login: "user@example.com",
  password: "securepassword",
});
// Save `newUser` in your database
```

### **🔑 Login & Generate JWTs**
```ts
const tokens = await authService.login(user, "user-password");
console.log(tokens); // { accessToken, refreshToken, sessionId }
```

### **🛡 Validate a Token & Session**
```ts
const user = await authService.validateSession(accessToken);
console.log(user); // { userId, sessionId }
```

### **🔓 Logout (Delete Session)**
```ts
await authService.logout(sessionId);
```

---

## 🔑 WebAuthn (Passkey) Support
### **1️⃣ Generate WebAuthn Challenge**
```ts
const challenge = await authService.registerPasskey(userId, "example.com", "preferred", storeChallenge);
```

### **2️⃣ Verify Passkey Response**
```ts
const verified = await authService.verifyPasskey(response, userId, "example.com", "https://example.com", getStoredChallenge, getCredential);
```

---

## 🏗 API Route Example (Express.js)
```ts
import express from "express";
const app = express();
app.use(express.json());

app.post("/login", async (req, res) => {
  try {
    const { userId, password } = req.body;
    const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
    if (!user) return res.status(400).json({ error: "User not found" });

    const tokens = await authService.login(user, password);
    res.json(tokens);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});
```

---

## 📜 License
**BSD-3-Clause** License. See `LICENSE` for details.

---

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 🔗 Links
- **GitHub Repository**: [Secure Auth](https://github.com/mikelambson/secure-auth)
- **Issues & Bugs**: [Submit an Issue](https://github.com/mikelambson/secure-auth/issues)

