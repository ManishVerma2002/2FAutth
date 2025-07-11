import {Router} from 'express';
import passport from 'passport';
import {register, login, authStatus,  logout , setup2FA , verify2FA , reset2FA} from '../controllers/authController.js'


const router = Router();


// Registration Route
router.post('/register', register);

// Login Route
router.post('/login', passport.authenticate('local'),  login); 

// Auth Status Route
router.get('/status', authStatus);

// Logout Route
router.post('/logout', logout);

// 2FA Route
router.post('/2fa/setup',(req,res,next) => {
    if(req.isAuthenticated()) return next();
    res.status(401).json({ msg : 'Unauthorized ' })
}, setup2FA);

// Verify Route
router.post('/2fa/verify',(req,res,next) => {
    if(req.isAuthenticated()) return next();
    res.status(401).json({ msg : 'Unauthorized ' })
}, verify2FA);

// Logout Route
router.post('/2fa/reset',(req,res,next) => {
    if(req.isAuthenticated()) return next();
    res.status(401).json({ msg : 'Unauthorized ' })
}, reset2FA);

export default router;