const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config = require('config')
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();


// /api/auth
router.post(
    '/register',
    [
        check('email', 'Incorrect email').isEmail(),
        check('password', 'Password min length must be 6 symbols')
            .isLength({min: 6})
    ],
    async (request, response) => {
        try {
            const errors = validationResult(request);

            if (!errors.isEmpty()) {
                return response.status(400).json({
                    errors: errors.array(),
                    message: 'Incorrect data in registration'
                })
            }

            const {email, password} = request.body;

            const candidate = await User.findOne({email});

            if (candidate) {
                return response.status(400).json({message: 'This user is already exists'})
            }

            const hashedPassword = await bcrypt.hash(password, 12);
            const user = new User({email, password: hashedPassword});

            await user.save();

            response.status(201).json({message: 'User was successfully created'})
        } catch (e) {
            response.status(500).json({message: "Something went wrong, please try again"});
        }
    });

// /api/login
router.post(
    '/login',
    [
        check('email', 'Please enter a valid email').normalizeEmail().isEmail(),
        check('password', 'Enter password').exists()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Incorrect login data'
                })
            }

            const {email, password} = req.body;

            const user = await User.findOne({email});

            if (!user) {
                return res.status(400).json({message: 'User is not found'});
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({message: 'Invalid password, try again'});
            }

            const token = jwt.sign(
                {userId: user.id},
                config.get('jwtSecret'),
                {expiresIn: '1h'}
            );

            res.json({token, userId: user.id});

        } catch (e) {
            res.status(500).json({message: 'Something went wrong, try again'});
        }
    })
module.exports = router;