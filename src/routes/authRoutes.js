const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const auth = require('../middleware/auth');


router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/profile', auth, function(req,res){
    res.send('Hello World')
}
);

router.post('/request-password-reset', authController.requestPasswordReset);
router.post('/verify-otp', authController.verifyOTP);
router.post('/reset-password', authController.resetPassword)

module.exports = router;