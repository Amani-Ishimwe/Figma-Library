const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto')


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

exports
