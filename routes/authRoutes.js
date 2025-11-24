const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");

// Auth routes

router.post("/login", authController.loginUser);
router.post("/register", authController.registerUser);
router.post("/refresh", authController.refresh);



module.exports = router;
