require("dotenv").config();
import { NextFunction, Request, Response } from "express";
import prisma from "../utils/prisma";
import jwt from "jsonwebtoken";
import { sendToken } from "../utils/send-token";
import nodemailer from "nodemailer";

// NodeMailer transporter for sending emails (and simulating SMS)
const transporter = nodemailer.createTransport({
  service: "gmail", // Or your preferred email service
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// In-memory OTP storage with expiry
interface OtpData {
  otp: string;
  expiry: number;
}
const otpCache = new Map<string, OtpData>();

// Generate OTP
const generateOtp = () => Math.floor(1000 + Math.random() * 9000).toString();

// Store OTP with expiry in cache (default 5 minutes)
const storeOtp = (identifier: string, otp: string, ttl: number = 300000) => {
  const expiry = Date.now() + ttl;
  otpCache.set(identifier, { otp, expiry });

  // Automatically delete OTP after expiry
  setTimeout(() => otpCache.delete(identifier), ttl);
};

// Validate OTP
const isOtpValid = (identifier: string, otp: string): boolean => {
  const otpData = otpCache.get(identifier);
  if (!otpData) return false;

  const { otp: storedOtp, expiry } = otpData;
  if (Date.now() > expiry) {
    otpCache.delete(identifier); // OTP expired
    return false;
  }

  return storedOtp === otp;
};

// Send OTP to driver's phone (via simulated SMS using email)
export const sendingOtpToPhone = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { phone_number } = req.body;

    const otp = generateOtp();
    storeOtp(phone_number, otp); // Store OTP in cache

    // Simulate SMS using email
    await transporter.sendMail({
      from: `"Ridewave" <${process.env.EMAIL_USER}>`,
      to: `${phone_number}@sms-gateway.com`, // Simulated SMS via email
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}`,
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

// Verify OTP for driver login
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

    if (driver) {
      sendToken(driver, res); // Send token to authenticated driver
    } else {
      res.status(404).json({
        success: false,
        message: "Driver not found",
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

// Verify OTP for driver registration
export const verifyPhoneOtpForRegistration = async (
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

    // Send email OTP for further verification
    await sendingOtpToEmail(req, res);
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
    });
  }
};

// Send OTP to driver's email
export const sendingOtpToEmail = async (req: Request, res: Response) => {
  try {
    const {
      name,
      email,
      userId,
      phone_number,
      vehicle_type,
      registration_number,
      registration_date,
      driving_license,
      vehicle_color,
      rate,
    } = req.body;

    const otp = generateOtp();
    storeOtp(email, otp); // Store OTP in cache for email verification

    const driverData = {
      name,
      email,
      phone_number,
      vehicle_type,
      registration_number,
      registration_date,
      driving_license,
      vehicle_color,
      rate,
    };
    const token = jwt.sign(
      {
        driverData,
        otp,
      },
      process.env.EMAIL_ACTIVATION_SECRET!,
      {
        expiresIn: "5m",
      }
    );

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

// Verify email OTP and create driver account
export const verifyingEmailOtp = async (req: Request, res: Response) => {
  try {
    const { otp, token } = req.body;

    const newDriver: any = jwt.verify(
      token,
      process.env.EMAIL_ACTIVATION_SECRET!
    );

    if (!isOtpValid(newDriver.driverData.email, otp)) {
      return res.status(400).json({
        success: false,
        message: "OTP is not correct or expired!",
      });
    }

    const {
      name,
      email,
      phone_number,
      vehicle_type,
      registration_number,
      registration_date,
      driving_license,
      vehicle_color,
      rate,
    } = newDriver.driverData;

    const driver = await prisma.driver.create({
      data: {
        name,
        email,
        phone_number,
        vehicle_type,
        registration_number,
        registration_date,
        driving_license,
        vehicle_color,
        rate,
      },
    });

    sendToken(driver, res); // Send token to the newly registered driver
  } catch (error) {
    console.log(error);
    res.status(400).json({
      success: false,
      message: "Your OTP is expired!",
    });
  }
};

// Get logged-in driver data
export const getLoggedInDriverData = async (req: any, res: Response) => {
  try {
    const driver = req.driver;

    res.status(201).json({
      success: true,
      driver,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch driver data",
    });
  }
};

// Get driver by ID
export const getDriverById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const driver = await prisma.driver.findUnique({
      where: {
        id: Number(id),
      },
    });

    if (!driver) {
      return res.status(404).json({
        success: false,
        message: "Driver not found",
      });
    }

    res.status(200).json({
      success: true,
      driver,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Error fetching driver",
    });
  }
};

// Get all new drivers (example for fetching drivers who are newly registered)
export const getNewDrivers = async (req: Request, res: Response) => {
  try {
    const drivers = await prisma.driver.findMany({
      where: {
        status: "New", // Assuming "New" is a status for new drivers
      },
    });

    res.status(200).json({
      success: true,
      drivers,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Error fetching new drivers",
    });
  }
};

// Get driver rides
export const getAllRides = async (req: any, res: Response) => {
  try {
    const rides = await prisma.rides.findMany({
      where: {
        driverId: req.driver?.id,
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

// Update driver status
export const updateDriverStatus = async (req: any, res: Response) => {
  try {
    const { status } = req.body;

    const driver = await prisma.driver.update({
      where: {
        id: req.driver.id!,
      },
      data: {
        status,
      },
    });

    res.status(201).json({
      success: true,
      driver,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Failed to update status",
    });
  }
};

// Update ride status for a driver
export const updatingRideStatus = async (req: any, res: Response) => {
  try {
    const { rideId, rideStatus } = req.body;

    // Validate input
    if (!rideId || !rideStatus) {
      return res.status(400).json({ success: false, message: "Invalid input data" });
    }

    const driverId = req.driver?.id;
    if (!driverId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Fetch the ride data to get the rideCharge
    const ride = await prisma.rides.findUnique({
      where: {
        id: rideId,
      },
    });

    if (!ride) {
      return res.status(404).json({ success: false, message: "Ride not found" });
    }

    const rideCharge = ride.charge;

    // Update ride status
    const updatedRide = await prisma.rides.update({
      where: {
        id: rideId,
        driverId,
      },
      data: {
        status: rideStatus,
      },
    });

    if (rideStatus === "Completed") {
      // Update driver stats if the ride is completed
      await prisma.driver.update({
        where: {
          id: driverId,
        },
        data: {
          totalEarning: {
            increment: rideCharge,
          },
          totalRides: {
            increment: 1,
          },
        },
      });
    }

    res.status(201).json({
      success: true,
      updatedRide,
    });
  } catch (error: any) {
    console.error(error);
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};


// get drivers data with id
export const getDriversById = async (req: Request, res: Response) => {
  try {
    const { ids } = req.query as any;
    console.log(ids,'ids')
    if (!ids) {
      return res.status(400).json({ message: "No driver IDs provided" });
    }

    const driverIds = ids.split(",");

    // Fetch drivers from database
    const drivers = await prisma.driver.findMany({
      where: {
        id: { in: driverIds },
      },
    });

    res.json(drivers);
  } catch (error) {
    console.error("Error fetching driver data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// creating new ride
export const newRide = async (req: any, res: Response) => {
  try {
    const {
      userId,
      charge,
      status,
      currentLocationName,
      destinationLocationName,
      distance,
    } = req.body;

    const newRide = await prisma.rides.create({
      data: {
        userId,
        driverId: req.driver.id,
        charge: parseFloat(charge),
        status,
        currentLocationName,
        destinationLocationName,
        distance,
      },
    });
    res.status(201).json({ success: true, newRide });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
};



