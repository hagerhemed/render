const {User} = require('../models/user');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { auth, restrictTo } = require("../middlewares/auth");
const{getForgotPasswordView,sendForgotPasswordLink, getResetPasswordView, resetThePassword} = require("../controllers/passwordController")
const{forgotPassword,resetPassword} = require("../controllers/passwordController")

  const nodemailer = require('nodemailer');
  const mg = require('nodemailer-mailgun-transport');



router.get(`/`, async (req, res) =>{
    const userList = await User.find().select('-passwordHash');

    if(!userList) {
        res.status(500).json({success: false})
    } 
    res.json(userList);
})

router.get('/:id',auth,restrictTo('Admin'), async(req,res)=>{
    const user = await User.findById(req.params.id).select('-passwordHash');

    if(!user) {
        res.status(500).json({message: 'The user with the given ID was not found.'})
    } 
    res.status(200).json(user);
})

router.post('/', async(req, res) => {
const newUser= new User(req.body);
await newUser.save();

if(!newUser)
return res.status(400).json('the user cannot be created!')

   res.status(201).json({data:{User:newUser}});
})

router.patch('/:id',async (req, res)=> {

    const userExist = await User.findById(req.params.id);
    let newPassword
    if(req.body.password) {
        newPassword = bcrypt.hashSync(req.body.password, 10)
    } else {
        newPassword = userExist.password;
    }

    const user = await User.findByIdAndUpdate(
        req.params.id,
        {
            name: req.body.name,
            email: req.body.email,
            password: newPassword,
            phone: req.body.phone,
            isAdmin: req.body.isAdmin,
            street: req.body.street,
            apartment: req.body.apartment,
            zip: req.body.zip,
            city: req.body.city,
            country: req.body.country,
        },
        { new: true}
    )

    if(!user)
    return res.status(400).json('the user cannot be created!')

    res.json(user);
})

router.post('/login', async (req,res) => {
    const user = await User.findOne({email: req.body.email})
    const secret = process.env.secret;
    if(!user) {
        return res.status(400).json('The user not found');
    }

    if(user && bcrypt.compareSync(req.body.password, user.password)) {
        const token = jwt.sign(
            {
                id: user.id,
                role:user.role,
            },
            secret,
            {expiresIn : '1d'}
        )
       
        res.status(200).json({user: user.email , token: token}) 
    } else {
       res.status(400).json('password is wrong!');
    }

    
})








router.post('/register', async (req, res) => {
    try {
      const newUser = new User(req.body);
      await newUser.save();
      res.status(201).json({ data: { User: newUser } });
    } catch (err) {
      if (err.name === 'ValidationError' && err.errors.email) {
        // Email already exists error
        return res.status(400).json({ error: err.errors.email.message });
      }
      // Handle other errors
      return res.status(400).json({ error: err.message });
    }
  });


router.delete('/:id',auth, (req, res)=>{
    User.findByIdAndDelete(req.params.id).then(user =>{
        if(user) {
            return res.status(200).json({success: true, message: 'the user is deleted!'})
        } else {
            return res.status(404).json({success: false , message: "user not found!"})
        }
    }).catch(err=>{
       return res.status(500).json({success: false, error: err}) 
    })
})

router.get("/get/count",auth,restrictTo('Admin'), async (req, res) => {
    const userCount = await User.find().count();
  
    if (!userCount) {
      return res.status(500).json({ success: false });
    }
  
    res.json({ userCount });
  });


  
  
  // Set up Mailtrap transport
  // const authen = {
  //   auth: {
  //       api_key: process.env.MAILGUN_API_KEY,
  //       domain: process.env.MAILGUN_DOMAIN
  //   }
  // };
  
  // const transporter = nodemailer.createTransport(mg(authen));
  
  // app.post('/forgot-password', (req, res) => {
  //   // Get the user's email from the request body
  //   const { email } = req.body;
  
  //   // Generate a reset token (e.g., a random string)
  //   const resetToken = generateResetToken();
  
  //   // Store the reset token associated with the user's email in your database
  
  //   // Send the reset password email
  //   const mailOptions = {
  //     from: 'hagergaber799@gmail.com',
  //     to: email,
  //     subject: 'Reset your password',
  //     text: `Please click the following link to reset your password: http://localhost:4029/reset-password/${resetToken}`
  //   };
  
  //   transporter.sendMail(mailOptions, (error, info) => {
  //     if (error) {
  //       console.log(error);
  //       res.status(500).send('Error sending email');
  //     } else {
  //       console.log('Email sent: ' + info.response);
  //       res.status(200).send('Email sent successfully');
  //     }
  //   });
  // });
  
  // function generateResetToken() {
  //   // Implement your own token generation logic
  //   return 'your_reset_token';
  // }


// router.route("/forgot-password")
// .get(getForgotPasswordView)
// .post(sendForgotPasswordLink)

// router.route("/reset-password/:userId/:token")
// .get(getResetPasswordView)
// .post(resetThePassword)


router.route('/forgotPassword').post(forgotPassword)
router.route('/resetPassword/:token').patch(resetPassword)


 module.exports =router;