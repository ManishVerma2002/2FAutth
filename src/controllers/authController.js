import bcrypt from "bcryptjs";
import User from "../models/user.js";
import speakeasy from 'speakeasy';
import qrCode from "qrcode";
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      isMfaActive: false,
    });

    await newUser.save();

    res.status(201).json({
      msg: "User is created successfully",
      user: {
        username: newUser.username,
        isMfaActive: newUser.isMfaActive,
        createdAt: newUser.createdAt,
      },
    });
  } catch (err) {
    res.status(500).json({
      error: "Error registering user",
      message: err.message || err.toString(),
    });
  }
};


export const login = async (req, res) => {
  console.log("the authenticated user : ", req.user);
  res.status(200).json({
    msg: "user login successful",
    username: req.user.username,
    isMfaActive: req.user.isMfaActive,
  });
};

export const authStatus = async (req, res) => {
  if (req.user) {
    res.status(200).json({
    msg: "user login successful",
    username: req.user.username,
    isMfaActive: req.user.isMfaActive,
    });
  }else{
    res.status(401).json({msg : 'Unathorized user'})
  }
};

export const logout = async (req, res) => {
  if (!req.user) return res.status(401).json({ msg: 'Unauthorized user' });

  req.logout((err) => {
    if (err) return res.status(400).json({ msg: 'User not logged in' });
    res.status(200).json({ msg: 'Logout successful' });
  });
};


export const setup2FA = async (req, res) => {
   try {
    const user = req.user; 
    if (!user) {
      return res.status(401).json({ msg: "Unauthorized" });
    }

    const secret = speakeasy.generateSecret();
    console.log('The secret object is:', secret);

    user.twoFactorSecret = secret.base32;
    user.isMfaActive = true;
    await user.save();

    const url = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `${user.username}`, 
      issuer: 'www.dipeshmalvia.com',
      encoding: 'base32' 
    });

    const qrImageUrl = await qrCode.toDataURL(url);

    res.status(200).json({
      secret: secret.base32,
      qrCode: qrImageUrl
    });
  } catch (err) {
    console.error("Error in setup2FA:", err); 
    res.status(500).json({
      err: 'Error setting up 2FA',
      msg: err.message || err.toString()
    });
  }
};

export const verify2FA = async (req, res) => {
  const user = req.user; 

  if (!user || !user.twoFactorSecret) {
    return res.status(400).json({ msg: '2FA not set up' });
  }

  const { token } = req.body;

  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token,
  });

  if (verified) {
    const jwtToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.status(200).json({ msg: '2FA successful', token: jwtToken });
  } else {
    res.status(400).json({ msg: 'Invalid 2FA token' });
  }
};


export const reset2FA = async (req, res) => {
  try{

    const user = req.user;
    user.twoFactorSecret = "";
    user.isMfaActive = false;
    await user.save();
    res.status(200).json({ msg : '2Fa reset successful' })

  }catch(err){
    res.status(500).json({
      err : 'Error reseting 2FA',
      msg : err
    })
  }
};
