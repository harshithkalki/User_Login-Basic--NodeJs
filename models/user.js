const { text } = require('express');
const mongoose=require('mongoose');

const userschema=new mongoose.Schema({
    username: {
        type:String,required:true,unique:true
    },
    password: {
        type:String,
        required:true
    }
});
const usermodel=mongoose.model('userdb',userschema);
module.exports=usermodel;