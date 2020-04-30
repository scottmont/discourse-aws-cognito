var express = require('express')
var router = express.Router()

router.get('/', function (req, res) {
  res.send(req.json)
  req.session.errors = null;
});

module.exports = router
