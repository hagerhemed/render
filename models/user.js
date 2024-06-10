const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto')

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: async function(email) {
        const user = await this.constructor.findOne({ email });
        return !user;
      },
      message: 'The email "{VALUE}" is already registered.'
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 8, // Enforce minimum password length for security
  },
  confirmPassword: {
    type: String,
    required: true,
    validate: {
      validator: function(confirmPassword) {
        return this.password === confirmPassword;
      },
      message: 'Passwords must match',
    },
  },
  phone: {
    type: String,
    required: true,
  },
  postalCode: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: 'user',
    enum: ['user', 'admin', 'seller'],
  },
  street: {
    type: String,
    default: '',
    required: true,
  },
  apartment: {
    type: String,
    default: '',
  },
  zip: {
    type: String,
    default: '',
  },
  city: {
    type: String,
    required: true,
  },
  building:{
    type: String,
    required: true,
  },
  landmark:{
    type: String,
    required: true,
  },
  country: {
    type: String,
    default: '',
  },
  passwordChangedAt:Date,
  passwordResetToken:String,
  passwordResetTokenExpires:Date

});

// Password hashing middleware (executed before saving the user)
// userSchema.pre('save', async function (next) {
//   if (this.isModified('password')) { // Only hash if password is modified
//     try {
//       const salt = await bcrypt.genSalt(10);
//       const hashPassword = await bcrypt.hash(this.password, salt);
//       this.password = hashPassword;
//       next();
//     } catch (err) {
//       next(err); // Handle potential hashing errors
//     }
//   } else {
//     next(); // Skip hashing if password is not modified
//   }
// });


// Password hashing middleware (executed before saving the user)
userSchema.pre('save', async function (next) {
  if (this.isModified('password') || this.isModified('confirmPassword')) { // Hash password and confirmPassword if either is modified
    try {
      const salt = await bcrypt.genSalt(10);
      const hashPassword = await bcrypt.hash(this.password, salt);
      const hashConfirmPassword = await bcrypt.hash(this.confirmPassword, salt);
      this.password = hashPassword;
      this.confirmPassword = hashConfirmPassword;
      next();
    } catch (err) {
      next(err); // Handle potential hashing errors
    }
  } else {
    next(); // Skip hashing if neither password nor confirmPassword is modified
  }
});


userSchema.virtual('id').get(function () {
        return this._id.toHexString();
     });
    
     userSchema.set('toJSON', {
         virtuals: true,
    });

    // userSchema.methods.createResetPasswordToken =function(){
    //   const resetToken = crypto.randomBytes(32,toString('hex'))

    //   this.passwordResetToken=crypto.createHash('sha256').update(resetToken).digest('hex')
    //   this.passwordResetTokenExpires = Date.now() + 10* 60 * 1000
    //   console.log(resetToken,this.passwordResetToken)

    //   return resetToken
    // }
    userSchema.methods.createResetPasswordToken = function() {
      const resetToken = crypto.randomBytes(32).toString('hex');
    
      this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
      this.passwordResetTokenExpires = Date.now() + 10 * 60 * 1000;
      console.log(resetToken, this.passwordResetToken);
    
      return resetToken;
    };



// No virtual ID or `toJSON` is necessary for password reset functionality

// Export the User model and schema
exports.User = mongoose.model('User', userSchema);
exports.userSchema = userSchema;