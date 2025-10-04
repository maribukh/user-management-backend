import express from "express";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";

const { Pool } = pkg;
const app = express();

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://user-management-app-itransition.onrender.com";
const SECRET_KEY =
  process.env.SECRET_KEY || "mySuperStrongSecretKeyForJWT12345";

app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json());

const pool = new Pool({
  connectionString:
    "postgresql://user_management_db_o6o4_user:TzrePklJcDBPVSsSX92GVaLu3yXoFodH@dpg-d3g0ko7fte5s73ciqivg-a/user_management_db_o6o4",
  ssl: {
    rejectUnauthorized: false,
  },
});

const initializeDatabase = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        registration_time TIMESTAMPTZ DEFAULT NOW(),
        last_login_time TIMESTAMPTZ,
        status VARCHAR(50) DEFAULT 'unverified',
        verification_token VARCHAR(255)
    );
  `;
  const createIndexQuery = `
    CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_lower ON users (LOWER(email));
  `;
  try {
    await pool.query(createTableQuery);
    await pool.query(createIndexQuery);
    console.log(
      "Database initialized successfully (table and index checked/created)."
    );
  } catch (err) {
    console.error("Error initializing database:", err);
  }
};

const transporter = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "32716a422f78e3",
    pass: "5ed966fc266fa9",
  },
});

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      decoded.id,
    ]);
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.status === "blocked")
      return res.status(403).json({ message: "User is blocked" });
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

app.get("/", (req, res) => {
  res.status(200).json({ message: "Welcome to the User Management API" });
});

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const newUserQuery = `
      INSERT INTO users (name, email, password_hash, verification_token) 
      VALUES ($1, $2, $3, $4) RETURNING id
    `;
    await pool.query(newUserQuery, [
      name,
      email,
      passwordHash,
      verificationToken,
    ]);

    const verificationLink = `${FRONTEND_URL}/verify-email/${verificationToken}`;

    await transporter.sendMail({
      from: '"Your App Name" <your_email@example.com>',
      to: email,
      subject: "Please verify your email address",
      html: `<b>Please click the following link to verify your email:</b> <a href="${verificationLink}">${verificationLink}</a>`,
    });

    res.status(201).json({
      message:
        "Registration successful. Please check your email to verify your account.",
    });
  } catch (error) {
    console.error("Error during registration:", error);
    if (error.code === "23505") {
      return res
        .status(400)
        .json({ message: "User with this email already exists" });
    }
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/verify-email/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const result = await pool.query(
      "SELECT * FROM users WHERE verification_token = $1",
      [token]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ message: "Invalid verification token." });
    }

    await pool.query(
      "UPDATE users SET status = 'active', verification_token = NULL WHERE id = $1",
      [user.id]
    );

    res.status(200).json({ message: "Email verified successfully." });
  } catch (error) {
    console.error("Error during email verification:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email) = LOWER($1)",
      [email]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user.status === "unverified") {
      return res
        .status(403)
        .json({ message: "Please verify your email before logging in." });
    }

    if (user.status === "blocked") {
      return res
        .status(403)
        .json({ message: "User is blocked and cannot log in" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    await pool.query("UPDATE users SET last_login_time = NOW() WHERE id = $1", [
      user.id,
    ]);

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, registration_time, last_login_time, status FROM users ORDER BY id ASC"
    );
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/users/update-status", authenticateToken, async (req, res) => {
  const { userIds, status } = req.body;
  if (!userIds || !userIds.length || !status) {
    return res
      .status(400)
      .json({ message: "User IDs and status are required" });
  }

  try {
    const query = "UPDATE users SET status = $1 WHERE id = ANY($2::int[])";
    await pool.query(query, [status, userIds]);
    res.status(200).json({ message: "Users status updated successfully" });
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/users/delete", authenticateToken, async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || !userIds.length) {
    return res.status(400).json({ message: "User IDs are required" });
  }

  try {
    const query = "DELETE FROM users WHERE id = ANY($1::int[])";
    await pool.query(query, [userIds]);
    res.status(200).json({ message: "Users deleted successfully" });
  } catch (error) {
    console.error("Error deleting users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post(
  "/api/users/delete-unverified",
  authenticateToken,
  async (req, res) => {
    try {
      const query = "DELETE FROM users WHERE status = 'unverified'";
      const result = await pool.query(query);
      res.status(200).json({
        message: `${result.rowCount} unverified users deleted successfully`,
      });
    } catch (error) {
      console.error("Error deleting unverified users:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

initializeDatabase();

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
