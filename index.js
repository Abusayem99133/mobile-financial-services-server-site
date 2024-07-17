const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bodyParser = require("body-parser");
const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:5174"],
  credentials: true,
  optionSuccessStatus: 200,
};

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());

//Start MongoDB here
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ddlv3rx.mongodb.net/?appName=Cluster0`;

// console.log(uri);
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server (optional starting in v4.7)
    await client.connect();

    // Collections
    const userCollection = client.db("userDB").collection("user");

    // Allowed roles
    const allowedRoles = ["user", "agent"];

    // Register User
    app.post("/register", async (req, res) => {
      const { name, pin, number, email, role } = req.body;

      // Basic validation
      if (!name || !pin || !number || !email || !role) {
        return res.status(400).send({ error: "All fields are required" });
      }

      // Validate role
      if (!allowedRoles.includes(role)) {
        return res.status(400).send({ error: "Invalid role" });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).send({ error: "Invalid email format" });
      }

      // Validate mobile number format (assuming a simple 11-digit number for example)
      const mobileRegex = /^\d{11}$/;
      if (!mobileRegex.test(number)) {
        return res.status(400).send({ error: "Invalid mobile number format" });
      }

      // Check if user with the same email or mobile already exists
      const existingUser = await userCollection.findOne({
        $or: [{ email }, { number }, { role }],
      });
      if (existingUser) {
        return res.status(400).send({
          error:
            "User with the same email or mobile number and role already exists",
        });
      }

      // Hash the PIN
      const hashedPin = await bcrypt.hash(pin, 5);

      // Create a new user object
      const newUser = {
        name,
        pin: hashedPin,
        number,
        email,
        role,
        status: "pending",
        balance: 0,
      };

      // Insert the new user into the database
      const result = await userCollection.insertOne(newUser);
      res.status(201).send({ insertedId: result.insertedId });
    });

    // Login
    app.post("/login", async (req, res) => {
      const { identifier, pin } = req.body;

      try {
        const user = await userCollection.findOne({
          $or: [{ email: identifier }, { number: identifier }],
        });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        const isPinValid = await bcrypt.compare(pin, user.pin);
        if (!isPinValid) {
          return res.status(401).json({ error: "Invalid PIN" });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });
        res.json({ token, user: { name: user.name, email: user.email } });
      } catch (error) {
        res.status(500).json({ error: "Login failed" });
      }
    });

    // Protect routes middleware
    const authenticateToken = (req, res, next) => {
      const token = req.header("Authorization");
      if (!token) return res.status(401).json({ error: "Access denied" });

      try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
      } catch (error) {
        res.status(400).json({ error: "Invalid token" });
      }
    };

    // Profile
    app.get("/profile", authenticateToken, async (req, res) => {
      try {
        const user = await userCollection.findOne({
          _id: new ObjectId(req.user.userId),
        });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        res.json({ user });
      } catch (error) {
        res.status(500).json({ error: "Error fetching profile" });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Financial pay Server is Running");
});

app.listen(port, () => {
  console.log(`Financial pay server is running on port: ${port}`);
});
