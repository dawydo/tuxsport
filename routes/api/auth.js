const express = require('express')
const router = express.Router()
const auth = require('../../middleware/auth')
const User = require('../../models/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator');

// @route   GET api/auth
// @desc    Auth Route
// @access  Public
router.get('/', auth, async (req, res) => {
    // Get data from MongoDB by token. Exclude password
    try {
        const user = await User.findById(req.user.id).select('-password')
        res.json(user)
    } catch (err) {
        console.error(err.message)
        res.status(500).send('Server Error')
    }
})
 

// @route   POST api/auth
// @desc    Authenticate user & get token
// @access  Public
router.post(
    '/',
    [
      check('email', 'Please include a valid email').isEmail(),
      check('password', 'Password is require').exists()
    ],
    async (req, res) => {
      const errors = validationResult(req)
      if(!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() })
      }
  
      const { email, password } = req.body
  
      try {
          // See if user exist
          let user = await User.findOne({ email })
  
          if (!user) {
              return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] })
          }
  
          
          // Match user password with bycript(check and compare)
          const isMatch = await bcrypt.compare(password, user.password)
          
          if (!isMatch) {
            return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] })
          }
  

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