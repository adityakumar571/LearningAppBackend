import User from "../models/User.modal.js";
import { asyncHandler } from "../utils/asynchandler.js";
import {apiError } from "../utils/apiError.js";
import {apiResponse} from "../utils/apiResponse.js"
import { HTTP_STATUS } from "../utils/httpStatus.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { generateOTP } from "../utils/generateOTP.js";
import { sendWhatsappOTP } from "../utils/sendOTP.js";
import mongoose from "mongoose";

const OTP_EXPIRATION_TIME = 5 * 60 * 1000; // 5 min
const isDev = process.env.NODE_ENV !== "production";
// ------------------- REGISTER / LOGIN (OTP) -------------------
 const registerOrLogin = asyncHandler(async (req, res) => {
  const { userId, phone, password, name, gender = "Male", role = "User" } = req.body;

  // ----------- VALIDATIONS -----------
  if (!userId || !phone || !password) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json(
      new apiResponse(
        HTTP_STATUS.BAD_REQUEST,
        null,
        "userId, phone, and password are required"
      )
    );
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json(
      new apiResponse(
        HTTP_STATUS.BAD_REQUEST,
        null,
        "Phone number must be exactly 10 digits"
      )
    );
  }

  let user = await User.findOne({ userId });

  // ================= EXISTING USER =================
  if (user) {
    if (user.phone !== phone) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json(
        new apiResponse(
          HTTP_STATUS.BAD_REQUEST,
          null,
          "Phone number does not match userId"
        )
      );
    }

    const isPasswordValid = await bcrypt.compare(password, user.password || "");
    if (!isPasswordValid) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json(
        new apiResponse(
          HTTP_STATUS.BAD_REQUEST,
          null,
          "Invalid password"
        )
      );
    }

    // ----------- OTP GENERATE -----------
    const otp = phone === "1111111111" ? "0101" : generateOTP();
    const otpExpiration = new Date(Date.now() + OTP_EXPIRATION_TIME);

    user.otp = otp;
    user.otpExpiration = otpExpiration;
    await user.save();

    // Send OTP only in production
    if (!isDev) {
      await sendWhatsappOTP(phone, otp);
    }

    return res.status(HTTP_STATUS.OK).json(
      new apiResponse(
        HTTP_STATUS.OK,
        {
          _id: user._id,
          userId: user.userId,
          phone: user.phone,
          isNew: user.isNew,
          ...(isDev && { otp }) // ✅ OTP ONLY FOR TESTING
        },
        "Existing user - OTP sent"
      )
    );
  }

  // ================= NEW USER =================
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = await User.create({
    userId,
    phone,
    password: hashedPassword,
    name,
    gender,
    role,
    isNew: true
  });

  // ----------- OTP GENERATE -----------
  const otp = phone === "1111111111" ? "0101" : generateOTP();
  const otpExpiration = new Date(Date.now() + OTP_EXPIRATION_TIME);

  newUser.otp = otp;
  newUser.otpExpiration = otpExpiration;
  await newUser.save();

  // Send OTP only in production
  if (!isDev) {
    await sendWhatsappOTP(phone, otp);
  }

  return res.status(HTTP_STATUS.CREATED).json(
    new apiResponse(
      HTTP_STATUS.CREATED,
      {
        _id: newUser._id,
        userId: newUser.userId,
        phone: newUser.phone,
        isNew: true,
        ...(isDev && { otp }) // ✅ OTP ONLY FOR TESTING
      },
      "New user created - OTP sent"
    )
  );
});



// ------------------- VERIFY OTP -------------------
 const verifyOtp = asyncHandler(async (req, res) => {
  const { phone, otp } = req.body;

  if (!phone || !otp) {
    return res.status(HTTP_STATUS.BAD_REQUEST)
      .json(new apiResponse(HTTP_STATUS.BAD_REQUEST, null, "Phone and OTP are required"));
  }

  const user = await User.findOne({ phone });
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  if (user.otp !== otp) return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "Invalid OTP");

  if (user.otpExpiration < new Date()) return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "OTP expired");

  const token = user.generateAuthToken();

  res.status(HTTP_STATUS.OK)
    .json(new apiResponse(HTTP_STATUS.OK, { _id: user._id, userId: user.userId, phone: user.phone, name: user.name, role: user.role, authToken: token }, "OTP verified successfully"));
});

// ------------------- RESEND OTP -------------------
 const resendOtp = asyncHandler(async (req, res) => {
  const { phone } = req.body;

  if (!phone) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "Phone number is required");

  const user = await User.findOne({ phone });
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  const otp = generateOTP();
  const otpExpiration = new Date(Date.now() + OTP_EXPIRATION_TIME);
  await sendWhatsappOTP(phone, otp);

  user.otp = otp;
  user.otpExpiration = otpExpiration;
  await user.save();

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, { phone, otp }, "OTP resent successfully"));
});

// ------------------- LOGIN WITH PASSWORD -------------------
 const loginWithPassword = asyncHandler(async (req, res) => {
  const { userId, password } = req.body;

  if (!userId || !password) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "userId and password required");

  const user = await User.findOne({ userId });
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  if (!user.password) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "Password not set");

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "Invalid password");

  const token = user.generateAuthToken();

  res.status(HTTP_STATUS.OK)
    .json(new apiResponse(HTTP_STATUS.OK, { _id: user._id, userId: user.userId, phone: user.phone, role: user.role, authToken: token }, "Login successful"));
});

// ------------------- CREATE PASSWORD -------------------
 const createPassword = asyncHandler(async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "userId and password required");

  const user = await User.findOne({ userId });
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");
  if (user.password) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "Password already set");

  user.password = await bcrypt.hash(password, 10);
  await user.save();

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, null, "Password created successfully"));
});

// ------------------- UPDATE PASSWORD -------------------
 const updatePassword = asyncHandler(async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;
  if (!userId || !oldPassword || !newPassword) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "userId, oldPassword, and newPassword required");

  const user = await User.findOne({ userId });
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
  if (!isOldPasswordValid) return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "Old password is invalid");

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, null, "Password updated successfully"));
});

// ------------------- USER PROFILE -------------------
 const getProfile = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  const user = await User.findById(userId).select("-password -otp -otpExpiration");
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, user, "Profile fetched successfully"));
});

// ------------------- UPDATE USER -------------------
 const updateUserById = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id);
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  Object.keys(req.body).forEach(key => user[key] = req.body[key]);
  await user.save();

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, user, "User updated successfully"));
});

// ------------------- DELETE USER -------------------
 const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id);
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  // Soft delete
  user.isDeleted = true;
  await user.save();

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, null, "User soft-deleted successfully"));
});

// ------------------- GET ALL USERS -------------------
const getAllUsers = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search, role } = req.query;
  const match = { isDeleted: { $ne: true } };

  if (role) match.role = role;

  let pipeline = [{ $match: match }];

  if (search) {
    const regex = new RegExp(search, "i");
    pipeline.push({ $match: { $or: [{ name: regex }, { phone: regex }, { email: regex }] } });
  }

  pipeline.push({ $sort: { createdAt: -1 } });
  pipeline.push({ $skip: (page - 1) * limit }, { $limit: parseInt(limit) });
  pipeline.push({ $project: { password: 0, otp: 0, otpExpiration: 0 } });

  const users = await User.aggregate(pipeline);
  const total = await User.countDocuments(match);

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, { users, totalUsers: total, currentPage: Number(page), totalPages: Math.ceil(total / limit) }, "Users fetched successfully"));
});

// ------------------- GET USER BY ID -------------------
const getUserById = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  if (!mongoose.Types.ObjectId.isValid(userId)) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "Invalid user ID");

  const user = await User.findById(userId).select("-password");
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, user, "User fetched successfully"));
});

// ------------------- UPDATE ROLE -------------------
const updateUserRole = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  let { role } = req.body;
  if (!userId || !role) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "User ID and role required");

  const ALLOWED_ROLES = ["User","Student","Admin","SuperAdmin","Teacher","Accountant"];
  role = role.trim();
  if (!ALLOWED_ROLES.includes(role)) return apiError(res, HTTP_STATUS.BAD_REQUEST, false, "Invalid role value");

  const user = await User.findById(userId);
  if (!user) return apiError(res, HTTP_STATUS.NOT_FOUND, false, "User not found");

  user.role = role;
  await user.save();

  res.status(HTTP_STATUS.OK).json(new apiResponse(HTTP_STATUS.OK, { userId: user._id, role }, "Role updated successfully"));
});

export{
    registerOrLogin,
    verifyOtp,
    resendOtp,
    loginWithPassword,
    createPassword,
    updatePassword,
    getProfile,
    updateUserById,
    deleteUser,
    getAllUsers,
    getUserById,
    updateUserRole
};