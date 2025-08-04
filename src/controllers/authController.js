const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto')
const prisma = require('../services/prismaClient')



exports.register = async (req,res)=>{
  const {first_name,last_name,contact_no,email,password,role ='user'} = req.body;

  const hashedPassword = bcrypt.hashSync(password, 10);

  try{
    const user = await prisma.users.create({
      data:{
        first_name,
        last_name,
        contact_no,
        email,
        password: hashedPassword
      }
    })
    res.status(201).json(user)
  }catch(error){
    console.error('Error creating user:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }

}    
  exports.login = async (req , res) =>{
    const { email, password } = req.body;
    try{
      const user = await prisma.users.findUnique({
        where: { email}
      })

      if (!user){
        return res.status(404).json({ message: 'User not found' });
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password' });
      }
      const token = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } });

    }catch(error){
      console.log(error)
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
exports.logout = (req, res) => {
  // Invalidate the token on the client side by removing it from storage
  res.status(200).json({ message: 'Logout successful' });
}

exports.requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
  const tokenExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

  try {
    const user = await prisma.users.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    await prisma.users.update({
      where: { email },
      data: {
        reset_token: otpHash,
        reset_token_expires: tokenExpires,
      },
    });

    // Send OTP email
    await transporter.sendMail({
      to: email,
      subject: 'Your OTP for Password Reset',
      text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
    });

    res.json({ message: 'OTP sent to email' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;
  const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

  try {
    const user = await prisma.users.findFirst({
      where: {
        email,
        reset_token: otpHash,
        reset_token_expires: {
          gt: new Date(), // token expiry > now
        },
      },
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired OTP' });

    res.json({ message: 'OTP verified' });

  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.resetPassword = async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await prisma.users.update({
      where: { email },
      data: {
        password: hashedPassword,
        reset_token: null,
        reset_token_expires: null,
      },
    });

    res.json({ message: 'Password reset successful' });

  } catch (error) {
    res.status(500).json({ message: 'Error updating password' });
  }
};