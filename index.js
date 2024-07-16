const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ddlv3rx.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    const userCollection = client.db("userDB").collection("user");

    // Register User
    app.post("/register", async (req, res) => {
      const { name, pin, number, email } = req.body;

      // Basic validation
      if (!name || !pin || !number || !email) {
        return res.status(400).send({ error: "All fields are required" });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).send({ error: "Invalid email format" });
      }

      // Validate mobile number format (assuming a simple 10 digit number for example)
      const mobileRegex = /^\d{11}$/;
      if (!mobileRegex.test(number)) {
        return res.status(400).send({ error: "Invalid mobile number format" });
      }

      // Check if user with the same email or mobile already exists
      const existingUser = await userCollection.findOne({
        $or: [{ email }, { number }],
      });
      if (existingUser) {
        return res.status(400).send({
          error: "User with the same email or mobile number already exists",
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
        status: "pending",
        balance: 0,
      };

      // Insert the new user into the database
      const result = await userCollection.insertOne(newUser);
      res.status(201).send({ insertedId: result.insertedId });
    });
  } finally {
    // Uncomment this if you want to close the connection after the operations
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Financial services is Running");
});

app.listen(port, () => {
  console.log(`Mobile financial is Running on Port ${port}`);
});
