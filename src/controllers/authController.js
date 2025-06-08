const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto')
const transporter = require('./emailService')



exports.register = (req,res)=>{
  const {first_name,last_name,contact_no,email,password,role ='user'} = req.body;

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.query(
    'INSERT INTO users (first_name, last_name, contact_no, email, password,role) VALUES (?, ?, ?, ?, ?,?)',
    [first_name, last_name, contact_no, email, hashedPassword,role],
    (error, results) => {
      if (error) {
        console.error('Error inserting user:', error);
        return res.status(500).json({ message: 'Internal server error' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    }
  );
}
  exports.login = (req , res) =>{
    const { email, password } = req.body;

    db.query(
      'SELECT * FROM users WHERE email = ?',
      [email],
      (error, results) => {
        if (error) {
          console.error('Error fetching user:', error);
          return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
          return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = results[0];

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, role:user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            first_name: user.first_name,
            last_name: user.last_name,
            contact_no: user.contact_no,
            email: user.email,
            role: user.role
          }
        });
      }
    );
  }
exports.logout = (req, res) => {
  // Invalidate the token on the client side by removing it from storage
  res.status(200).json({ message: 'Logout successful' });
}

exports.requestPasswordReset = (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
  const tokenExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    db.query(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?',
      [otpHash, tokenExpires, email],
      (err2) => {
        if (err2) return res.status(500).json({ message: 'Server error' });

        
        transporter.sendMail({
          to: email,
          subject: 'Your OTP for Password Reset',
          text: `Your OTP is: ${otp}. It expires in 10 minutes.`,
        }, (mailErr) => {
          if (mailErr)
            console.error('Error sending email:', mailErr) 
            return res.status(500).json({ message: 'Failed to send email' });

          res.json({ message: 'OTP sent to email' });
        });
      }
    );
  });
};

exports.verifyOTP = (req, res) => {
  const { email, otp } = req.body;
  const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

  db.query(
    'SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_token_expires > NOW()',
    [email, otpHash],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(400).json({ message: 'Invalid or expired OTP' });
      }

      res.json({ message: 'OTP verified' });
    }
  );
};


exports.resetPassword = async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 12);

  db.query(
    'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE email = ?',
    [hashedPassword, email],
    (err) => {
      if (err) return res.status(500).json({ message: 'Error updating password' });

      res.json({ message: 'Password reset successful' });
    }
  );
};

exports.resetPassword = (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  db.query(
    'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
    [tokenHash],
    async (err, results) => {
      if (err || results.length === 0)
        return res.status(400).json({ message: 'Invalid or expired token' });

      const hashedPassword = await bcrypt.hash(newPassword, 12);

      // Update password and clear token
      db.query(
        'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
        [hashedPassword, results[0].id],
        (err2) => {
          if (err2) return res.status(500).json({ message: 'Error updating password' });
          res.json({ message: 'Password reset successful' });
        }
      );
    }
  );
};

