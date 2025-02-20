#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { generateKeyPairSync } from "crypto";
import * as readline from "readline";

// Paths
const CONFIG_DIR = path.join(process.cwd(), ".secure-auth");
const PRIVATE_KEY_PATH = path.join(CONFIG_DIR, "private-key.pem");
const PUBLIC_KEY_PATH = path.join(CONFIG_DIR, "public-key.pem");
const ENV_PATH = path.join(process.cwd(), ".env");

// CLI prompt utility
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

async function askQuestion(query: string): Promise<string> {
  return new Promise((resolve) => rl.question(query, resolve));
}

// Ensure `.secure-auth/` directory exists
function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    console.log(`✅ Created config directory: ${CONFIG_DIR}`);
  }
}

// Generate a new Ed25519 key pair
function generateKeys() {
  console.log("🔑 Generating new Ed25519 key pair...");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);

  console.log(`✅ New Private Key: ${PRIVATE_KEY_PATH}`);
  console.log(`✅ New Public Key: ${PUBLIC_KEY_PATH}`);
}

// Update `.env` file with key paths
function updateEnv() {
  let envContent = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, "utf8") : "";

  if (!envContent.includes("JWT_PRIVATE_KEY=")) {
    envContent += `\nJWT_PRIVATE_KEY=${PRIVATE_KEY_PATH}`;
  }
  if (!envContent.includes("JWT_PUBLIC_KEY=")) {
    envContent += `\nJWT_PUBLIC_KEY=${PUBLIC_KEY_PATH}`;
  }

  fs.writeFileSync(ENV_PATH, envContent);
  console.log(`✅ Updated .env file with key paths.`);
}

// Main function
async function main() {
  console.log("🔧 Secure Auth Setup");

  const answer = await askQuestion("⚠️ Keys already exist. Overwrite? (yes/no): ");
  if (answer.toLowerCase() !== "yes") {
    console.log("❌ Operation cancelled.");
    rl.close();
    return;
  }

  ensureConfigDir();
  generateKeys();
  updateEnv();
  rl.close();
  console.log("🎉 Secure Auth setup complete!");
}

main();
