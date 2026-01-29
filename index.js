import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import cors from "cors";

import authRoutes from "./router/authRoutes.js"

dotenv.config();
const app = express();

const clientUrl = process.env.CLIENT_URL;
app.use(
  cors({
    origin: clientUrl || "*",
    credentials: true,
  })
);

app.use(express.json());

app.use("/api/auth", authRoutes);


//const PORT = process.env.PORT || 5000;
const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  connectDB();
});