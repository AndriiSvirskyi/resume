const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt-nodejs');

const models = require('../models');

// POST is register
router.post('/register', (req, res) => {
  const login = req.body.login;
  const password = req.body.password;
  const passwordConfirm = req.body.passwordConfirm;

  if (!login || !password || !passwordConfirm) {
    const fields = [];
    if (!login) fields.push('login');
    if (!password) fields.push('password');
    if (!passwordConfirm) fields.push('passwordConfirm');

    res.json({
      ok: false,
      error: 'Всі поля повинні бути заповненні!',
      fields
    });
  } else if (!/^[a-zA-Z0-9]+$/.test(login)) {
    res.json({
      ok: false,
      error: 'Тільки латинські букви та цифри!',
      fields: ['login']
    });
  } else if (login.length < 3 || login.length > 16) {
    res.json({
      ok: false,
      error: 'Довжина логіну від 3 до 16 символів!',
      fields: ['login']
    });
  } else if (password !== passwordConfirm) {
    res.json({
      ok: false,
      error: 'Паролі не співпадають!',
      fields: ['password', 'passwordConfirm']
    });
  } else if (password.length < 5) {
    res.json({
      ok: false,
      error: 'Мінімальна довжина паролю 5 символів!',
      fields: ['password']
    });
  } else {
    models.User.findOne({
      login
    }).then(user => {
      if (!user) {
        bcrypt.hash(password, null, null, (err, hash) => {
          models.User.create({
            login,
            password: hash
          })
            .then(user => {
              console.log(user);
              req.session.userId = user.id;
              req.session.userLogin = user.login;
              res.json({
                ok: true
              });
            })
            .catch(err => {
              console.log(err);
              res.json({
                ok: false,
                error: 'Помилка, спробуйте пізніше!'
              });
            });
        });
      } else {
        res.json({
          ok: false,
          error: 'Ім*я зайняте!',
          fields: ['login']
        });
      }
    });
  }
});

// POST is register
router.post('/login', (req, res) => {
  const login = req.body.login;
  const password = req.body.password;

  if (!login || !password) {
    const fields = [];
    if (!login) fields.push('login');
    if (!password) fields.push('password');

    res.json({
      ok: false,
      error: 'Всі поля повинні бути заповнені!',
      fields
    });
  } else {
    models.User.findOne({
      login
    })
      .then(user => {
        if (!user) {
          res.json({
            ok: false,
            error: 'Логін і пароль невірні!',
            fields: ['login', 'password']
          });
        } else {
          bcrypt.compare(password, user.password, function(err, result) {
            if (!result) {
              res.json({
                ok: false,
                error: 'Логін і пароль невірні!',
                fields: ['login', 'password']
              });
            } else {
              req.session.userId = user.id;
              req.session.userLogin = user.login;
              res.json({
                ok: true
              });
            }
          });
        }
      })
      .catch(err => {
        console.log(err);
        res.json({
          ok: false,
          error: 'Помилка спробуйте пізніше!'
        });
      });
  }
});

// GET for logout
router.get('/logout', (req, res) => {
  if (req.session) {
    // delete session object
    req.session.destroy(() => {
      res.redirect('/');
    });
  } else {
    res.redirect('/');
  }
});

module.exports = router;
