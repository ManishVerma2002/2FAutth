import bcrypt from "bcryptjs";
import User from "../models/user.js";

export const register = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

    // Check if user already exists
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
    console.log(newUser, "msg : user is created succesfully");
    await newUser.save();
    res.status(201).json({
      msg: "user is created successfully",
      user: newUser,
    });
  } catch (err) {
    res.status(500).json({ error: "Error registering user", message: err });
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
  if(!req.user)res.status(401).json({msg : 'Unathorized user'});
  req.logout((err)=>{
    if (err) return res.status(400).json({msg : ' user not logged in'});
     res.status(200).json({msg : ' logout successful'});
  })
};

export const setup2FA = async (req, res) => {
  res.send("2FA setup route working");
};

export const verify2FA = async (req, res) => {
  res.send("2FA verify route working");
};

export const reset2FA = async (req, res) => {
  res.send("2FA reset route working");
};
