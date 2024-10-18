import express from "express";
import {
  getAllRides,
  getLoggedInUserData,
  PriceCalculation,
  registerUser,
  sendingOtpToEmail,
  verifyingEmail,
  verifyOtp,
} from "../controllers/user.controller";
import { isAuthenticated } from "../middleware/isAuthenticated";

const userRouter = express.Router();

userRouter.post("/registration", registerUser);

userRouter.post("/verify-otp", verifyOtp);

userRouter.post("/email-otp-request", sendingOtpToEmail);

userRouter.put("/email-otp-verify", verifyingEmail);

userRouter.get("/me", isAuthenticated, getLoggedInUserData);

userRouter.get("/get-rides", isAuthenticated, getAllRides);

userRouter.post("/ride-price", isAuthenticated, PriceCalculation);
export default userRouter;
