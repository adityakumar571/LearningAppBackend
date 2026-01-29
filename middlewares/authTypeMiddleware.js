import jwt from "jsonwebtoken";
import User from "../models/User.modal.js";
import { asyncHandler } from "../utils/asynchandler.js";
import { apiError } from "../utils/apiError.js";
import { HTTP_STATUS } from "../utils/httpStatus.js"; // Make sure you export HTTP_STATUS from a file

// Middleware to verify JWT token
export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    // Get token from cookies or Authorization header
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "Unauthorized request: No token provided");
    }

    // Verify token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // Find the user associated with token
    const user = await User.findById(decodedToken?.userId).select("-password -authToken");
    if (!user) {
      return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "Invalid access token: User not found");
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, error?.message || "Invalid access token");
  }
});

// Middleware to authorize user based on account type
export const authorizeUserType = (...allowedTypes) => {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      return apiError(res, HTTP_STATUS.UNAUTHORIZED, false, "Unauthorized access: No user data available");
    }

    if (!allowedTypes.includes(req.user.accountType)) {
      return apiError(res, HTTP_STATUS.FORBIDDEN, false, "Forbidden: You do not have access to this resource");
    }

    next();
  });
};
