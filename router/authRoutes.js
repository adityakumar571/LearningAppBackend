// authRoutes.js
import { Router } from "express";
import {
  registerOrLogin,
  verifyOtp,
  resendOtp,
  loginWithPassword,
  createPassword,
  updatePassword,
  getProfile,
  updateUserById,
  getUserById,
  deleteUser,
  getAllUsers,
  updateUserRole,
} from "../controllers/authContollers.js";
import { verifyJWT, authorizeUserType } from "../middlewares/authTypeMiddleware.js";

const router = Router();

// ------------------- AUTH -------------------
// Signup / Login (OTP based)
router.post("/registerOrLogin", registerOrLogin);  
router.post("/verifyOtp", verifyOtp);             
router.post("/resendOtp", resendOtp);           

// Login with email/password
router.post("/loginWithPassword", loginWithPassword);

// Create / Update Password
router.post("/createPassword", createPassword);              
router.post("/updatePassword", verifyJWT, updatePassword);  // Protected

// ------------------- USER PROFILE -------------------
router.get("/profile", verifyJWT, getProfile);               // Logged-in user profile
router.patch("/update/:id", verifyJWT, updateUserById);     // Update profile

// ------------------- ADMIN / ROLE MANAGEMENT -------------------
router.get("/getAllUsers", verifyJWT, getAllUsers);
router.get("/user/:userId", verifyJWT, getUserById);
router.put("/updateRole/:userId", verifyJWT, updateUserRole);
router.delete("/delete/:id", verifyJWT,deleteUser);

export default router;
