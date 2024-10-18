require("dotenv").config();
import { NextFunction, Request, Response } from "express";
import prisma from "../utils/prisma";
import jwt from "jsonwebtoken";
import { sendToken } from "../utils/send-token";
import nodemailer from "nodemailer";
import geolib from "geolib";

interface Location {
  latitude: number;
  longitude: number;
}

interface PricingOptions {
  trafficFactor?: number;
  weatherFactor?: number;
  timeFactor?: number;
}

const toRadians = (degrees: number): number => {
  return degrees * (Math.PI / 180);
};

// NodeMailer transporter for sending emails
const transporter = nodemailer.createTransport({
  service: "gmail", // Or your preferred service
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// In-memory cache for OTP storage with expiry times
interface OtpData {
  otp: string;
  expiry: number;
}

const otpCache = new Map<string, OtpData>(); // Key is phone number or email

// Function to generate OTP
const generateOtp = () => Math.floor(1000 + Math.random() * 9000).toString();

// Function to store OTP in the cache with an expiry time (5 minutes)
const storeOtp = (identifier: string, otp: string, ttl: number = 300000) => {
  const expiry = Date.now() + ttl; // TTL in milliseconds
  otpCache.set(identifier, { otp, expiry });

  // Automatically remove OTP after expiry
  setTimeout(() => otpCache.delete(identifier), ttl);
};

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

// Register new user and send OTP to phone (simulating SMS via email)
export const registerUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { phone_number } = req.body;
    const otp = generateOtp();
    storeOtp(phone_number, otp); // Store OTP in cache

    // Simulate sending SMS via email
    await transporter.sendMail({
      from: `"Ridewave" <${process.env.EMAIL_USER}>`,
      to: `${phone_number}@sms-gateway.com`, // Simulating SMS via email
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}`, // OTP code for the user
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

// Verify OTP
export const verifyOtp = async (
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

    // Check if the user exists
    const isUserExist = await prisma.user.findUnique({
      where: {
        phone_number,
      },
    });

    if (isUserExist) {
      await sendToken(isUserExist, res); // Send token for existing user
    } else {
      // Create a new account
      const user = await prisma.user.create({
        data: {
          phone_number: phone_number,
        },
      });
      res.status(200).json({
        success: true,
        message: "OTP verified successfully!",
        user: user,
      });
    }
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
      message: "Something went wrong!",
    });
  }
};

// Sending OTP to email
export const sendingOtpToEmail = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, name, userId } = req.body;

    const otp = generateOtp();
    storeOtp(email, otp); // Store OTP in cache

    const user = {
      userId,
      name,
      email,
    };
    const token = jwt.sign(
      {
        user,
        otp,
      },
      process.env.EMAIL_ACTIVATION_SECRET!,
      {
        expiresIn: "5m",
      }
    );

    // Send OTP via email
    await transporter.sendMail({
      from: `"Ridewave" <${process.env.EMAIL_USER}>`,
      to: email,
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

// Verifying email OTP
export const verifyingEmail = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { otp, token } = req.body;

    const newUser: any = jwt.verify(
      token,
      process.env.EMAIL_ACTIVATION_SECRET!
    );

    if (!isOtpValid(newUser.user.email, otp)) {
      return res.status(400).json({
        success: false,
        message: "OTP is not correct or expired!",
      });
    }

    const { name, email, userId } = newUser.user;

    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (user?.email === null) {
      const updatedUser = await prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          name: name,
          email: email,
        },
      });
      await sendToken(updatedUser, res);
    }
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
      message: "Your OTP is expired!",
    });
  }
};

// Get logged-in user data
export const getLoggedInUserData = async (req: any, res: Response) => {
  try {
    const user = req.user;

    res.status(201).json({
      success: true,
      user,
    });
  } catch (error) {
    console.log(error);
  }
};

// Getting user rides
export const getAllRides = async (req: any, res: Response) => {
  try {
    const rides = await prisma.rides.findMany({
      where: {
        userId: req.user?.id,
      },
      include: {
        driver: true,
        user: true,
      },
    });
    res.status(201).json({
      rides,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve rides",
    });
  }
};


// Haversine formula to calculate the distance between two locations
const haversineDistance = (loc1: Location, loc2: Location): number => {
  const R = 6371; // Radius of the Earth in kilometers
  const dLat = toRadians(loc2.latitude - loc1.latitude);
  const dLon = toRadians(loc2.longitude - loc1.longitude);

  const lat1 = toRadians(loc1.latitude);
  const lat2 = toRadians(loc2.latitude);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(lat1) * Math.cos(lat2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c; // Distance in kilometers
};

// Ride price calculation based on distance and factors
const calculateRidePrice = (
  pickup: Location,
  destination: Location,
  surgeMultiplier: number,
  options: PricingOptions = {}
): string => {
  const BASE_FARE = 5;
  const RATE_PER_KM = 2;

  const { trafficFactor = 1, weatherFactor = 1, timeFactor = 1 } = options;

  const distanceInKm = haversineDistance(pickup, destination);

  let totalFare = BASE_FARE + distanceInKm * RATE_PER_KM;

  totalFare *= surgeMultiplier;
  totalFare *= trafficFactor;
  totalFare *= weatherFactor;
  totalFare *= timeFactor;

  return totalFare.toFixed(2);
};

// Main function to handle the price calculation API
export const PriceCalculation = async (req: any, res: Response) => {
  try {
    const { pickup, destination, surgeMultiplier, trafficFactor, weatherFactor, timeFactor } = req.body;

    if (!pickup || !destination || !surgeMultiplier) {
      return res.status(400).json({ success: false, message: "Invalid or missing parameters" });
    }

    const pickupLocation: Location = { latitude: pickup.latitude, longitude: pickup.longitude };
    const destinationLocation: Location = { latitude: destination.latitude, longitude: destination.longitude };

    const ridePrice = calculateRidePrice(
      pickupLocation,
      destinationLocation,
      surgeMultiplier,
      { trafficFactor, weatherFactor, timeFactor }
    );

    return res.status(200).json({ success: true, price: ridePrice });
  } catch (error:any) {
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
};