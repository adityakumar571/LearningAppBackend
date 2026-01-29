import { HTTP_STATUS } from "../utils/httpStatus.js";

export const notFound = (req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  error.statusCode = HTTP_STATUS.NOT_FOUND;
  next(error);
};


export const errorHandler = (err, req, res, next) => {
  const statusCode =
    err.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR;

  console.error("Error:", err.message);

  res.status(statusCode).json({
    success: false,
    statusCode,
    message: err.message || "Internal Server Error",
    stack:
      process.env.NODE_ENV === "production"
        ? undefined
        : err.stack,
  });
};
