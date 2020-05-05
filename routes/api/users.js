const express = require('express');
const router = express.Router();
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator');


const User = require('../../models/User')

// @route   POST api/users
// @desc    Register User
// @access  Public
router.post(
  '/',
  [
    check('name', 'Name is required!').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password require min 6 characters').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const { name, email, password } = req.body

    try {
        // See if user exist
        let user = await User.findOne({ email })

        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists' }] })
        }

        // Get user gravatar
        const avatar = gravatar.url(email, {
            s: '200', // Size
            r: 'pg',  // Rating
            d: 'mm'   // Default icon
        })

        user = new User({
            name,
            email,
            password,
            avatar
        })

        // Encrypt password
        const salt = await bcrypt.genSalt(10)

        user.password = await bcrypt.hash(password, salt)

        await user.save()


        // Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), 
        {expiresIn: 3600000000}, //MAKE IT 3600
        (err, token) => {
            if(err) throw err
            res.json({ token })
        }) 


    } catch (err) {
        console.log(err.message)
        res.status(500).send('Server error')
    }

    
  }
);

module.exports = router;
