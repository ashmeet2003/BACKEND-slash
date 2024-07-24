import mongoose, {Schema} from 'mongoose';
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs';

const userSchema = new Schema({
    username: {
        type : String,
        required: true,
        unique : true,
        lowercase : true,
        trim : true,
        index : true
    },
    email: {
        type : String,
        required: true,
        unique : true,
        lowercase : true,
        trim : true
    },
    fullName : {
        type : String,
        required: true,
        trim : true,
        index : true
    },
    phone: {
        type: Number,
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['admin', 'employee', 'hr'],
        default: 'employee'
    },
    avatar : {
        type : String,  //url cloudinary
        required: true
    },
    refreshToken : {
        type : String
    }
},
{
    timestamps : true
});

// Password hashing
userSchema.pre("save", async function (next) {
    //if not modified, simply return next
    if(!this.isModified("password")) return next();
  
    this.password = await bcrypt.hash(this.password, 10)
    next()
  })
  
  //inserting methods into schema
  userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
  }
  //injecting more methods
  userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
      {
        _id: this._id,
        email: this.email,
        username: this.username,
        fullName: this.fullName
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY
      }
    )
  }
  userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
      {
        _id: this._id,
          
      },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY
      }
    )
  }

export const User = mongoose.model("User", userSchema)