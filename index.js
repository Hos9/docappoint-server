const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// MONGODB URI set korte hobe

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`),
);

// ── JWT Middleware ────────────────────────────────────────────────────────────
const verifyToken = async (req, res, next) => {
  const authHeader = req?.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: "Forbidden" });
  }
};

// ── Main DB Logic ─────────────────────────────────────────────────────────────
async function run() {
  try {
    const db = client.db("DocAppoint");
    const appointmentsCollection = db.collection("appointments");

    // ── GET all appointments OR filtered by email ──────────────────────────
    // Public: GET /appointments — returns all (for "All Appointments" page via doctors.json on client)
    // Private: GET /appointments?email=x — returns only user's bookings
    app.get("/appointments", verifyToken, async (req, res) => {
      const { email } = req.query;
      const query = email ? { userEmail: email } : {};
      const result = await appointmentsCollection
        .find(query)
        .sort({ _id: -1 })
        .toArray();
      res.json(result);
    });

    // ── POST new appointment ───────────────────────────────────────────────
    app.post("/appointments", verifyToken, async (req, res) => {
      const appointment = req.body;
      appointment.createdAt = new Date();
      const result = await appointmentsCollection.insertOne(appointment);
      res.json(result);
    });

    // ── PATCH update appointment ───────────────────────────────────────────
    app.patch("/appointments/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const updateData = req.body;
      delete updateData._id;
      delete updateData.userEmail;
      delete updateData.doctorName;
      delete updateData.doctorId;

      const result = await appointmentsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateData },
      );
      res.json(result);
    });

    // ── DELETE appointment ─────────────────────────────────────────────────
    app.delete("/appointments/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const result = await appointmentsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.json(result);
    });

    console.log("Connected to MongoDB DocAppoint database.");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.json({ message: "DocAppoint Server is running!", status: "OK" });
});

// For local dev
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`DocAppoint server running on port ${PORT}`);
  });
}

module.exports = app;
