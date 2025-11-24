const User = require('../models/user');
const RefreshToken = require('../models/refreshToken');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Register a new user
exports.registerUser = async (req, res, next) => {
  try {
    const userData = req.body;

    const user = new User(userData);
    const savedUser = await user.save();

    res.status(201).json({
      success: true,
      data: savedUser,
    });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: Object.values(error.errors).reduce((acc, val) => {
          acc[val.path] = val.message;
          return acc;
        }, {}),
      });
    }
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Mobile number already exists',
      });
    }
    next(error);
  }
};

// Login user
exports.loginUser = async (req, res, next) => {
  try {
    const { mobile, password } = req.body;

    if (!mobile || !password) {
      return res.status(400).json({
        success: false,
        message: 'Mobile and password are required',
        errors: {
          mobile: !mobile ? 'Mobile is required' : undefined,
          password: !password ? 'Password is required' : undefined,
        },
      });
    }

    const user = await User.findOne({ mobile });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid mobile or password',
        errors: {
          mobile: 'Invalid Mobile number',
        },
      });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Invalid password',
        errors: {
          password: 'Invalid Password',
        },
      });
    }

    // Generate token (optional)
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secretkey', {
      expiresIn: '1d',
    });
    const refreshToken = await generateRefreshToken(user);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      user:{ id: user._id,
        name: user.name,
        mobile: user.mobile},
        token,
        refreshToken
    });
  } catch (error) {
    next(error);
  }
};

exports.refresh = async (req, res) => {
  try{
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ message: "Refresh token required" });
    console.log(refreshToken);
    // Check token in DB
    const stored = await RefreshToken.findOne({ token: refreshToken });
    if (!stored)
      return res.status(403).json({ message: "Invalid refresh token" });
    
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
      if (err) return res.status(403).json({ message: "Token expired/invalid" });

      const userObj = { _id: user.id, email: user.email };

      // Generate new tokens
      const newAccessToken = await generateAccessToken(userObj);
      const newRefreshToken = await generateRefreshToken(userObj);

      // Delete old refresh token
      await RefreshToken.deleteOne({ token: refreshToken });

      return res.json({
        message: "Token refreshed",
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    });
  }catch (error){
    console.log(error)
  }
  
};

// Generate Refresh token (long expiry)
async function generateRefreshToken(user) {
  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );
  await RefreshToken.create({
    token: refreshToken,
    userId: user._id,
  });

  return refreshToken;
}

async function generateAccessToken(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secretkey', {
      expiresIn: '1d',
    });
}