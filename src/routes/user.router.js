const { getAll, create, getOne, remove, update, verifyCode, login, logged, resetPassword, updatePassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const routerUser = express.Router();

routerUser.route('/')
    .get(verifyJWT,getAll)  //GET->  /users ------- Private EndPoint
    .post(create);  //POST ->  /users : Public Endpoint

routerUser.route('/login') //POST->  /users/login ---- Public EndPoint
    .post(login)

routerUser.route('/me')  //GET->  /users/me ---- Private EndPoint
    .get(verifyJWT, logged)

routerUser.route('/reset_password') //POST--> /users/reset_password -------- Public EndPoint
    .post(resetPassword)

routerUser.route('/:id')
    .get(verifyJWT,getOne)  //GET->  /users:id ------- Private EndPoint
    .delete(verifyJWT,remove) //DELETE->  /users/:id  -------- Private EndPoint
    .put(verifyJWT,update);  //PUT->  /users/:id ------- Private EndPoint

routerUser.route('/verify/:code') //GET->  /users/verify/:code ----- Public EndPoint
    .get(verifyCode)

routerUser.route('/reset_password/:code')// POST ->  /users/reset_password/:code -------- Public EndPoint
    .post(updatePassword)

module.exports = routerUser;