import mongoose from "mongoose";

export async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error("Missing MONGODB_URL or MONGODB_URI in environment");
  }

  // Use the database specified in the URI. Mongoose will create the DB on first write.
  await mongoose.connect(uri, {
    // options can be added here if needed
  });

  return mongoose.connection;
}

