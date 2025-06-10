const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
       user:'your_gmail.com',
       pass:'your_password' 
    }
})

module.exports = transporter