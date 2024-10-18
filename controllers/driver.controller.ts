require("dotenv").config();
import { NextFunction, Request, Response } from "express";
import prisma from "../utils/prisma";
import jwt from "jsonwebtoken";
import { sendToken } from "../utils/send-token";
import nodemailer from "nodemailer";

// NodeMailer transporter for sending emails
const transporter = nodemailer.createTransport({
  service: "gmail", // Or your preferred service
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Generate random OTP
const generateOtp = () => Math.floor(1000 + Math.random() * 9000).toString();

// In-memory cache for OTP storage with expiry times
interface OtpData {
  otp: string;
  expiry: number;
}

const otpCache = new Map<string, OtpData>(); // Key is phone number or email

// Function to check if OTP is valid
const isOtpValid = (identifier: string, otp: string): boolean => {
  const otpData = otpCache.get(identifier);
  if (!otpData) return false;

  const { otp: storedOtp, expiry } = otpData;
  if (Date.now() > expiry) {
    otpCache.delete(identifier); // Delete expired OTP
    return false;
  }

  return storedOtp === otp;
};

// Function to store OTP in the cache with an expiry time
const storeOtp = (identifier: string, otp: string, ttl: number = 300000) => {
  const expiry = Date.now() + ttl; // TTL in milliseconds (default is 5 minutes)
  otpCache.set(identifier, { otp, expiry });

  // Automatically remove OTP after expiry
  setTimeout(() => otpCache.delete(identifier), ttl);
};

// sending OTP to phone (simulated using email)
export const sendingOtpToPhone = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { phone_number } = req.body;
    console.log(phone_number);

    const otp = generateOtp();
    storeOtp(phone_number, otp); // Store OTP in cache

    // Simulating SMS sending via email (can be replaced with real SMS gateway)
    await transporter.sendMail({
      from: `"Ridewave" <${process.env.EMAIL_USER}>`, // sender address
      to: `${phone_number}@sms-gateway.com`, // SMS gateway simulation via email
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}`, // Plain text OTP for SMS
    });

    res.status(201).json({
      success: true,
      message: "OTP sent to phone (via email simulation)",
    });
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
    });
  }
};

// verifying OTP for login (using cache)
export const verifyPhoneOtpForLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { phone_number, otp } = req.body;

    if (!isOtpValid(phone_number, otp)) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    const driver = await prisma.driver.findUnique({
      where: {
        phone_number,
      },
    });

    sendToken(driver, res);
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
      message: "Something went wrong!",
    });
  }
};

// sending OTP to email (using NodeMailer)
export const sendingOtpToEmail = async (req: Request, res: Response) => {
  try {
    const {
      name,
      country,
      phone_number,
      email,
      vehicle_type,
      registration_number,
      registration_date,
      driving_license,
      vehicle_color,
      rate,
    } = req.body;

    const otp = generateOtp();
    storeOtp(email, otp); // Store OTP in cache for the email

    const driver = {
      name,
      country,
      phone_number,
      email,
      vehicle_type,
      registration_number,
      registration_date,
      driving_license,
      vehicle_color,
      rate,
    };
    const token = jwt.sign(
      {
        driver,
        otp,
      },
      process.env.EMAIL_ACTIVATION_SECRET!,
      {
        expiresIn: "5m",
      }
    );

    // Send OTP via email
    await transporter.sendMail({
      from: `"Ridewave" <${process.env.EMAIL_USER}>`, // sender address
      to: email, // receiver's email
      subject: "Verify your email address!",
      html: `
        <p>Hi ${name},</p>
        <p>Your Ridewave verification code is ${otp}. If you didn't request this OTP, please ignore this email!</p>
        <p>Thanks,<br>Ridewave Team</p>
      `,
    });

    res.status(201).json({
      success: true,
      token,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Failed to send email",
    });
    console.log(error);
  }
};

// verifying email OTP (using cache)
export const verifyingEmailOtp = async (req: Request, res: Response) => {
  try {
    const { otp, token } = req.body;

    const newDriver: any = jwt.verify(
      token,
      process.env.EMAIL_ACTIVATION_SECRET!
    );

    if (!isOtpValid(newDriver.driver.email, otp)) {
      return res.status(400).json({
        success: false,
        message: "OTP is not correct or expired!",
      });
    }

    const {
      name,
      country,
      phone_number,
      email,
      vehicle_type,
      registration_number,
      registration_date,
      driving_license,
      vehicle_color,
      rate,
    } = newDriver.driver;

    const driver = await prisma.driver.create({
      data: {
        name,
        country,
        phone_number,
        email,
        vehicle_type,
        registration_number,
        registration_date,
        driving_license,
        vehicle_color,
        rate,
      },
    });

    sendToken(driver, res);
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
      message: "Your OTP is expired!",
    });
  }
};
