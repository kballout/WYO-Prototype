const router = require("express").Router();
const User = require("../model/User");
const Provider = require("../model/Provider");
const Manager = require("../model/Manager");
const EmailToken = require("../model/EmailToken");
const RefreshToken = require("../model/RefreshToken");
const ForgotPassword = require("../model/ForgotPassword");
const {
  regUserValid,
  regProviderValid,
  loginValidation,
} = require("../validation");
const crypto = require("crypto");
const { nanoid } = require("nanoid");
const sendEmail = require("../email");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../generateTokens");
const passport = require("passport");

//REGISTRATION
router.post("/register", async (req, res) => {
  console.log(req.body);
  //USER SIGN UP
  if (req.body.type === "User") {
    //check if email already exists
    const emailExists = await User.findOne({ email: req.body.email });
    if (emailExists) return res.status(400).send("Email already in use");

    //validation
    const data = req.body;
    data.dateOfBirth = new Date(req.body.dateOfBirth);
    const { error } = regUserValid.validate(data);
    if (error) return res.status(400).send(error.details[0].message);

    //hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(req.body.password, salt);

    //create new user
    const user = new User({
      email: req.body.email,
      name: req.body.name,
      dateOfBirth: req.body.dateOfBirth,
      phoneNumber: req.body.phoneNumber,
      password: hashedPass,
      address: req.body.address,
      city: req.body.city,
      zipCode: req.body.zipCode,
    });

    //save user in db
    try {
      await user.save();
    } catch (err) {
      res.status(500).send(err);
    }

    //generate token for email validation
    const token = new EmailToken({
      _userId: user._id,
      token: nanoid(10),
    });
    //save token
    try {
      await token.save();
    } catch (err) {
      res.status(500).send(err);
    }

    //send email
    const message = `Hello ${req.body.name}, Your confirmation code is ${token.token}`;
    await sendEmail(user.email, "WYO Email Verification", message);

    //generate access and refresh tokens and send to the user
    const access = generateAccessToken(user);
    const refresh = await generateRefreshToken(user);

    if (access !== "" && refresh !== "") {
      return res.status(200).json({
        refreshToken: refresh,
        accessToken: access,
        user: {
          name: user.name,
          role: user.type,
          verified: user.verificationStatus,
        },
      });
    } else {
      return res.status(500).send("Something went wrong");
    }
  }

  //PROVIDER SIGN UP
  else if (req.body.type === "Provider") {
    //check if email already exists
    const emailExists = await Provider.findOne({ email: req.body.email });
    if (emailExists) return res.status(400).send("Email already in use");

    //validation
    const { error } = regProviderValid.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    //hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(req.body.password, salt);

    //create new provider
    const user = new Provider({
      email: req.body.email,
      name: req.body.name,
      dateOfBirth: req.body.dateOfBirth,
      phoneNumber: req.body.phoneNumber,
      password: hashedPass,
      address: req.body.address,
      biography: req.body.biography,
      city: req.body.city,
      zipCode: req.body.zipCode,
    });

    //save user in db
    try {
      await user.save();
    } catch (err) {
      res.status(500).send(err);
    }

    //generate token for email validation
    const token = new EmailToken({
      _userId: user._id,
      token: nanoid(10),
    });
    //save token
    try {
      await token.save();
    } catch (err) {
      res.status(500).send(err);
    }

    //send email
    const message = `Hello ${req.body.name}, Your confirmation code is ${token.token}`;
    await sendEmail(user.email, "WYO Email Verification", message);

    //generate access and refresh tokens and send to the user
    const access = generateAccessToken(user);
    const refresh = await generateRefreshToken(user);

    if (access !== "" && refresh !== "") {
      return res.status(200).json({
        refreshToken: refresh,
        accessToken: access,
        user: {
          name: user.name,
          role: user.type,
          verified: user.verificationStatus,
        },
      });
    }
  }

  //MANAGER SIGN UP
  else if (req.body.type === "Manager") {
    //hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(req.body.password, salt);

    const user = new Manager({
      username: req.body.username,
      password: hashedPass,
    });

    //save in db
    try {
      await user.save();
    } catch (err) {
      res.status(500).send(err);
    }
  }
});

//LOGIN
router.post("/login", async (req, res) => {
  //validation
  const { error } = loginValidation.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  //check if user exists
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("Email or password is incorrect");

  //checking password
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword)
    return res.status(400).send("Email or password is incorrect");

  //generate access and refresh tokens and send to the user
  const access = generateAccessToken(user);
  const refresh = await generateRefreshToken(user);
  if (access !== "" && refresh !== "") {
    return res.status(200).json({
      refreshToken: refresh,
      accessToken: access,
      user: {
        name: user.name,
        role: user.type,
        verified: user.verificationStatus,
      },
    });
  }
});

//RESEND EMAIL VERIFICATION CODE
router.post("/resendverification",passport.authenticate("jwt", { session: false }), async (req, res) => {
    const user = req.user;
    if (!user) return res.status(400).send("invalid user");

    //checking if verified
    if (user.verificationStatus === false) {
      const oldToken = await EmailToken.findOne({ _userId: user._id });

      //if old token doesnt exists make a new one
      if (!oldToken) {
        const token = new EmailToken({ _userId: user._id, token: nanoid(10) });
        //save token
        try {
          await token.save();
        } catch (err) {
          res.status(500).send(err);
        }

        //resend verification email
        const message = `Hello ${user.name}, Your confirmation code is ${token.token}`;
        // await sendEmail(user.email, "WYO Email Verification", message);
      }

      //if old token exists update it with a new token
      else {
        const token = nanoid(10);
        await EmailToken.updateOne({ _userId: user._id }, { token: token });
        //resend verification email
        const message = `Hello ${user.name}, Your confirmation code is ${token.token}`;
        // await sendEmail(user.email, "WYO Email Verification", message);
      }
      return res.status(200).send("email sent for verification");
    } else {
      return res.send("User is already verified");
    }

    //   const token = req.body.token;
    //   if (token == null) return res.status("401").send("Invalid token");

    //   jwt.verify(token, process.env.ACCESS_TOKEN, async (err, info) => {
    //     if (err) return res.status(403).send("Authentication failure");

    //     const user = await User.findOne({ _id: info._id });
    //     if (!user) return res.status(400).send("Cannot find user!");

    //     //checking if verified
    //     if (user.verificationStatus === false) {
    //       const oldToken = await EmailToken.findOne({ _userId: user._id });

    //       //if old token doesnt exists make a new one
    //       if (!oldToken) {
    //         const token = new EmailToken({ _userId: user._id, token: nanoid(10) });
    //         //save token
    //         try {
    //           await token.save();
    //         } catch (err) {
    //           res.status(500).send(err);
    //         }

    //         //resend verification email
    //         const message = `Hello ${user.name}, Your confirmation code is ${token.token}`;
    //         await sendEmail(user.email, "WYO Email Verification", message);
    //       }

    //       //if old token exists update it with a new token
    //       else {
    //         const token = nanoid(10);
    //         await EmailToken.updateOne({ _userId: user._id }, { token: token });
    //         //resend verification email
    //         const message = `Hello ${user.name}, Your confirmation code is ${token.token}`;
    //         await sendEmail(user.email, "WYO Email Verification", message);
    //       }
    //       return res.status(200).send("email sent for verification");
    //     }
    //     else {
    //       return res.send("User is already verified");
    //     }
    //   });
  }
);

//GET ANOTHER TOKEN
router.post("/token", async (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null)
    return res.status(400).send("No refresh token found");

  const foundToken = await RefreshToken.findOne({ token: refreshToken });
  if (!foundToken)
    return res.status(401).send("Unauthorized");

  let info;
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN, async (err, user) => {
    if (err) return res.status(401).send("Unauthorized");
    info = await User.findOne({ _id: user._id });

    const accessToken = jwt.sign(
      {
        _id: info._id,
      },
      process.env.ACCESS_TOKEN,
      {
        expiresIn: process.env.ACCESS_TOKEN_EXP,
      }
    );
    //if successful
    return res.status(200).json({
      accessToken: accessToken,
      user: {
        name: info.name,
        role: info.type,
        verified: info.verificationStatus,
      },
    });
  });
});

//EMAIL VERIFICATION
router.post("/verify", passport.authenticate("jwt", { session: false }),async (req, res) => {
    const user = req.user;
    if (!user) return res.status(400).send("invalid user");
    if (!req.body.code) return res.status(400).send("invalid code");

    const token = await EmailToken.findOne({
      _userId: user._id,
      token: req.body.code,
    });
    if (!token) return res.status(400).send("invalid link");

    await User.updateOne({ _id: user.id }, { verificationStatus: true });
    await EmailToken.findByIdAndRemove(token.id);

    res.status(200).send("email has been verified!");
  }
);

//FORGOT PASSWORD
router.post("/forgotPassword", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("invalid user");

  //generate random code to be sent to the email of the user for password reset
  const oldToken = await ForgotPassword.findOne({ _userId: user._id });
  //if old token doesnt exists make a new one
  if (!oldToken) {
    const token = new ForgotPassword({
      _userId: user._id,
      token: nanoid(10),
    });
    //save token
    try {
      await token.save();
    } catch (err) {
      res.status(500).send(err);
    }
    //send email for password reset
    const message = `Hello ${user.name}, Your confirmation code to reset your password is ${token.token}`;
    await sendEmail(user.email, "WYO Password Reset", message);
  }
  //if old token exists update it with a new token
  else {
    const token = nanoid(10);
    await ForgotPassword.updateOne({ _userId: user._id }, { token: token });
    //send email for password reset
    const message = `Hello ${user.name}, Your confirmation code to reset your password is ${token.token}`;
    await sendEmail(user.email, "WYO Password Reset", message);
  }
  return res.status(200).send("email sent for password reset");
});

//RESET PASSWORD
router.post("/resetPassword", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("invalid user");

  //check if confirmation code is correct
  const token = await ForgotPassword.findOne({
    _userId: user._id,
    token: req.body.token,
  });
  if (!token) return res.status(400).send("invalid token");

  //hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPass = await bcrypt.hash(req.body.password, salt);

  //set new password
  await User.updateOne({ _id: user.id }, { password: hashedPass });
  //remove token from forgot password db
  await ForgotPassword.findByIdAndRemove(token.id);

  res.status(200).send("Password changed successfully");
});

//LOGOUT
router.delete("/logout", async (req, res) => {
  const token = await RefreshToken.findOne({ token: req.body.token });
  if (!token) return res.status("404").send("You are not logged in");
  await RefreshToken.findByIdAndRemove(token._id);
  res.status(200).send("logout successful");
});

module.exports = router;
