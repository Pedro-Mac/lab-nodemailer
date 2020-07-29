const { Router } = require('express');
const router = new Router();

const dotenv = require('dotenv');
dotenv.config();

const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  }
});
let user;
const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const { name, email, password } = req.body;
  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        confirmationToken: (Math.random() * 10000 * Math.random()).toString()
      });
    })
    .then(document => {
      req.session.user = document._id;
      user = document;

      res.redirect('/');
    })
    .then(() => {
      transport.sendMail({
        from: process.env.NODEMAILER_EMAIL,
        to: process.env.NODEMAILER_EMAIL,
        subject: 'Please verify your email to activate your account',
        html: `
        <html>
          <body>
            <h1>Hi ${user.name}</h1>
            <a href="http://localhost:3000/authentication/confirm-email?token=${user.confirmationToken}">Click here to verify your account: http://localhost:3000/authentication/confirm-email?token=${user.confirmationToken}</a>
          </body>
        </html>
        `
      });
    })
    .catch(error => {
      next(error);
    });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

const routeGuard = require('./../middleware/route-guard');
const { findOne } = require('./../models/user');

router.get('/authentication/confirm-email', routeGuard, (req, res, next) => {
  const token = req.query.token;
  console.log(token);

  User.findOneAndUpdate({ confirmationToken: token }, { status: 'active' })
    .then(user => {
      console.log(user.status);
    })
    .then(res.redirect('/profile'))
    .catch(err => {
      next(err);
    });
});

router.get('/profile', routeGuard, (req, res, next) => {
  const userId = req.session.user;

  let user;
  User.findById(userId)
    .then(data => {
      console.log(data);
      user = data;
    })
    .then(() => {
      res.render('profile', { user: user });
    });
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

module.exports = router;
