require("dotenv").config();

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// OTP Store
const otpStore = new Map();

// Rate Limiter
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    message: "Too many OTP requests. Please try again later."
  }
});

// Gmail Transporter
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// Verify transporter
transporter.verify((error, success) => {
  if (error) {
    console.log("MAIL ERROR:", error);
  } else {
    console.log("Mail server ready");
  }
});

// Generate OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Normalize email
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

// Health Check
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "MediStore OTP Backend running"
  });
});

// Send OTP
async function sendOtpHandler(req, res) {
  try {

    const email = normalizeEmail(req.body.email);
    const role = req.body.role === "admin" ? "admin" : "user";

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        success: false,
        message: "Valid email is required"
      });
    }

    if (!process.env.MAIL_USER || !process.env.MAIL_PASS) {
      return res.status(500).json({
        success: false,
        message: "Email service not configured"
      });
    }

    const otp = generateOtp();

    otpStore.set(email, {
      otp,
      role,
      attempts: 0,
      expiresAt: Date.now() + 5 * 60 * 1000
    });

    await transporter.sendMail({
      from: `"MediStore App" <${process.env.MAIL_USER}>`,
      to: email,
      subject: "Your MediStore Verification Code",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;border:1px solid #e0e0e0;border-radius:10px;padding:28px;">

          <h2 style="color:#1565C0;margin:0 0 8px">
            💊 MediStore
          </h2>

          <p style="color:#555;margin:0 0 16px">
            Your one-time verification code is:
          </p>

          <div style="
            font-size:40px;
            font-weight:bold;
            color:#1565C0;
            letter-spacing:10px;
            text-align:center;
            padding:20px 0;
            background:#F3F8FF;
            border-radius:8px;
          ">
            ${otp}
          </div>

          <p style="color:#777;font-size:13px;margin:16px 0 0">
            This code expires in <b>5 minutes</b>.
            Do not share with anyone.
          </p>

          <hr style="border:none;border-top:1px solid #eee;margin:20px 0">

          <p style="font-size:11px;color:#bbb;margin:0">
            If you did not request this, please ignore this email.
          </p>

        </div>
      `
    });

    console.log("OTP SENT TO:", email);

    return res.json({
      success: true,
      message: "OTP sent successfully",
      role
    });

  } catch (error) {

    console.error("SEND OTP ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to send OTP"
    });
  }
}

// Verify OTP
function verifyOtpHandler(req, res) {

  try {

    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();
    const requestRole = req.body.role;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required"
      });
    }

    const record = otpStore.get(email);

    if (!record) {
      return res.status(400).json({
        success: false,
        message: "OTP not found or already used"
      });
    }

    if (Date.now() > record.expiresAt) {

      otpStore.delete(email);

      return res.status(400).json({
        success: false,
        message: "OTP expired"
      });
    }

    if (record.attempts >= 5) {

      otpStore.delete(email);

      return res.status(400).json({
        success: false,
        message: "Too many wrong attempts"
      });
    }

    if (requestRole && record.role !== requestRole) {
      return res.status(400).json({
        success: false,
        message: "OTP role mismatch"
      });
    }

    if (record.otp !== otp) {

      record.attempts += 1;

      otpStore.set(email, record);

      return res.status(400).json({
        success: false,
        message: "Invalid OTP"
      });
    }

    otpStore.delete(email);

    return res.json({
      success: true,
      message: "OTP verified successfully",
      role: record.role
    });

  } catch (error) {

    console.error("VERIFY OTP ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "OTP verification failed"
    });
  }
}

// Routes
app.post("/send-otp", otpLimiter, sendOtpHandler);
app.post("/verify-otp", verifyOtpHandler);

app.post("/auth/send-otp", otpLimiter, sendOtpHandler);
app.post("/auth/verify-otp", verifyOtpHandler);

// Start Server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MediStore OTP Backend running on port ${PORT}`);
});