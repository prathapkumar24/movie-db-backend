const Baby = require('../models/baby');


// Create a new baby with milestones
exports.createBaby = async (req, res, next) => {
  try {
    const babyData = req.body;
    
    // Create and save new baby
    babyData.userId = req.user.id;
    const baby = new Baby(babyData);
    const savedBaby = await baby.save();
    
    res.status(201).json({
      success: true,
      data: savedBaby
    });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: Object.values(error.errors).map(val => val.message)
      });
    }
    next(error);
  }
};

// Get all babies
exports.getAllBabies = async (req, res, next) => {
  try {
    const babies = await Baby.find({ userId: req.user.id }).select('-__v');
    
    res.status(200).json({
      success: true,
      count: babies.length,
      data: babies
    });
  } catch (error) {
    next(error);
  }
};

// Get baby by ID
exports.getBabyById = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const baby = await Baby.findOne({ id, userId: req.user.id }).select('-__v');
    
    if (!baby) {
      return res.status(404).json({
        success: false,
        message: `Baby with ID ${id} not found 1`
      });
    }
    
    res.status(200).json({
      success: true,
      data: baby
    });
  } catch (error) {
    next(error);
  }
};

// Update baby by ID
exports.updateBaby = async (req, res, next) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    const baby = await Baby.findOne({ id, userId: req.user.id });
    
    if (!baby) {
      return res.status(404).json({
        success: false,
        message: `Baby with ID ${id} not found 2`
      });
    }
    
    // Update baby properties
    Object.keys(updateData).forEach(key => {
      if (key !== 'id' && key !== 'createdAt') { // Prevent updating these fields
        baby[key] = updateData[key];
      }
    });
    
    const updatedBaby = await baby.save();
    
    res.status(200).json({
      success: true,
      data: updatedBaby
    });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: Object.values(error.errors).map(val => val.message)
      });
    }
    next(error);
  }
};

// Delete baby by ID
exports.deleteBaby = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const baby = await Baby.findOneAndDelete({ id, userId: req.user.id });
    
    if (!baby) {
      return res.status(404).json({
        success: false,
        message: `Baby with ID ${id} not found 3`
      });
    }
    
    res.status(200).json({
      success: true,
      message: `Baby with ID ${id} successfully deleted`
    });
  } catch (error) {
    next(error);
  }
};

// Add a milestone to a baby
exports.addMilestone = async (req, res, next) => {
  try {
    const { id } = req.params;
    const milestone = req.body;
    
    const baby = await Baby.findOne({ id, userId: req.user.id });
    
    if (!baby) {
      return res.status(404).json({
        success: false,
        message: `Baby with ID ${id} not found 4`
      });
    }
    
    baby.milestones.push(milestone);
    const updatedBaby = await baby.save();
    
    res.status(200).json({
      success: true,
      data: updatedBaby.milestones[updatedBaby.milestones.length - 1]
    });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: Object.values(error.errors).map(val => val.message)
      });
    }
    next(error);
  }
};

// Update a milestone
exports.updateMilestone = async (req, res, next) => {
  try {
    const { id, milestoneId } = req.params;
    const milestoneData = req.body;
    
    const baby = await Baby.findOne({ id, userId: req.user.id });
    
    if (!baby) {
      return res.status(404).json({
        success: false,
        message: `Baby with ID ${id} not found 5`
      });
    }
    
    const milestoneIndex = baby.milestones.findIndex(m => m.id === milestoneId);
    
    if (milestoneIndex === -1) {
      return res.status(404).json({
        success: false,
        message: `Milestone with ID ${milestoneId} not found for this baby`
      });
    }
    
    // Update milestone
    Object.keys(milestoneData).forEach(key => {
      if (key !== 'id') {
        baby.milestones[milestoneIndex][key] = milestoneData[key];
      }
    });
    
    const updatedBaby = await baby.save();
    
    res.status(200).json({
      success: true,
      data: updatedBaby.milestones[milestoneIndex]
    });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: Object.values(error.errors).map(val => val.message)
      });
    }
    next(error);
  }
};

// Delete a milestone
exports.deleteMilestone = async (req, res, next) => {
  try {
    const { id, milestoneId } = req.params;
    
    const baby = await Baby.findOne({ id, userId: req.user.id });
    
    if (!baby) {
      return res.status(404).json({
        success: false,
        message: `Baby with ID ${id} not found 6`
      });
    }
    
    const milestoneIndex = baby.milestones.findIndex(m => m.id === milestoneId);
    
    if (milestoneIndex === -1) {
      return res.status(404).json({
        success: false,
        message: `Milestone with ID ${milestoneId} not found for this baby`
      });
    }
    
    baby.milestones.splice(milestoneIndex, 1);
    await baby.save();
    
    res.status(200).json({
      success: true,
      message: `Milestone with ID ${milestoneId} successfully deleted`
    });
  } catch (error) {
    next(error);
  }
};