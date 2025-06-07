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

router.post('/forgot-password', authController.requestPasswordReset)
router.post('/reset-password', authController.resetPassword);

module.exports = router;