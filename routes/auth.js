const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt-nodejs')

const models = require('../models');


router.post('/register',(req,res)=> {
    const login = req.body.login;
    const password = req.body.password;
    const passwordConfirm = req.body.passwordConfirm;

    if(!login || !password || !passwordConfirm){
        res.json({
            ok: false,
            error: 'Всі поля пивинні бути заповнені',
            fields: ['login', 'password', 'passwordConfirm']
        })
    } else if(login.length < 3 || login.length > 16){
        res.json({
            ok: false,
            error: 'Довжина логіна від 3 до 16 символів!',
            fields: ["login"]
        })
    } else if(password !== passwordConfirm){
        res.json({
            ok: false,
            error: 'Паролі не співпадають',
            fields: ["password","passwordConfirm"]
        })
    } else {
        models.User.findOne({
            login
        }).then(user => {
            if(!user){
                bcrypt.hash(password, null, null, (err,hash) =>{
                    models.User.create({
                        login,
                        password: hash
                    }).then(user => {
                        console.log(user);
                        res.json({
                            ok:true
                        })
                    }).catch(err=>{
                        console.log(err);
                        res.json({
                            ok:false,
                            error: 'Помилка, спробуйте пізніше!'
                        })
                    })
                })
            }else{
                res.json({
                    ok:false,
                    error: "Ім'я зайняте!",
                    fields: ['login']
                });
            }
        });




        
    }
});
module.exports = router;
