require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const router = express.Router();

router.post("/signup", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const role = req.body.role;
  const age = req.body.age;
  const password = req.body.password;

  if (!email || !password) {
    return res.json({ message: "invalid request" });
  }

  const userCheck = await User.findOne({ email: email });
  console.log("userCheck: ", userCheck);
  if (userCheck) {
    return res.json({ message: "email already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({
    name: name,
    email: email,
    password: hashedPassword,
    role: role,
    age: age,
  });
  await user.save();
  res.json({ message: "success" });
});

router.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.json({ message: "Email is invalid" });
  }
  const isPasswordMatching = await bcrypt.compare(
    req.body.password,
    user.password,
  );
  if (!isPasswordMatching) {
    return res.json({ message: "password invalid" });
  }
  try {
    const token = jwt.sign({ user: user._id }, process.env.SECRETE_CODE, {
      expiresIn: "1h",
    });
    return res.json({ message: "login successfull", token: token });
  } catch (err) {
    console.log(err);
    return res.json({ message: "server error" });
  }
});

module.exports = router;
