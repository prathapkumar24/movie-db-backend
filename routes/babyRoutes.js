const express = require("express");
const router = express.Router();
const babyController = require("../controllers/babyController");
const verifyToken = require('../middleware/authMiddleware');

// Baby routes
router.post("/", verifyToken, babyController.createBaby);
router.get("/", verifyToken, babyController.getAllBabies);
router.get("/:id", verifyToken, babyController.getBabyById);
router.put("/:id", verifyToken, babyController.updateBaby);
router.delete("/:id", verifyToken, babyController.deleteBaby);

// Milestone routes
router.post("/:id/milestones", verifyToken, babyController.addMilestone);
router.put("/:id/milestones/:milestoneId", verifyToken, babyController.updateMilestone);
router.delete("/:id/milestones/:milestoneId", verifyToken, babyController.deleteMilestone);



module.exports = router;
