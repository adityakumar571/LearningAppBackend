import mongoose from "mongoose";
import jwt from "jsonwebtoken";

const UserSchema = new mongoose.Schema(
  {
    
    userId: {
      type: String,
      required: true,
      unique: true,
    },
        name: String,
email: {
      type: String,
      trim: true,
      lowercase: true,
      unique: true,
      sparse: true,
      match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
    },
    phone: {
      type: String,
    },
    otp: String,
    otpExpiration: Date,

    isVerified: {
      type: Boolean,
      default: true,
      required: true,
    },
    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
    },

    role: {
      type: String,
      enum: ["User", "Student", "Admin", "SuperAdmin", "Teacher", "Accountant"],
      default: "User",
      required: true,
    },

    dob: Date,

    profilePic: String,
    
    password:String,

    address: String,

    fcmToken: {
      type: String,
    },
  },
  { timestamps: true }
);





UserSchema.methods.generateAuthToken = function () {
  return jwt.sign(
    { userId: this._id, role: this.role },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );
};

export default mongoose.model("User", UserSchema);
