const express = require('express');
const router = express.Router();

// @route POST api/users
// @desc Register User
// @access Public

router.post('/', (req, res) => {
  console.log(req.body);
  res.send('User route');
});

module.exports = router;
