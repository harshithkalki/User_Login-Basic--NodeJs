const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const userdb = require('./models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'hsajdhaksjdasbdsab*765$%#$aasggsdasguydgasg'

const app = express();
mongoose.connect('mongodb://localhost/login')
    .then((result) => {
        console.log('connected to the server');
        app.listen(3000);
    })
    .catch((err) => {
        console.log(err);
    })

app.use('/', express.json(path.join(__dirname, 'static')));
app.use(express.static('public'));


app.post('/api/change', async(req,res)=>{
    const {token,newpassword}=req.body;
    try{
    const user=jwt.verify(token,JWT_SECRET);
    const _id=user.id;
    const hashedpass=await bcrypt.hash(newpassword,10)
    await userdb.updateOne({_id},{$set:{password:hashedpass}})
    res.json({status:'ok'})
    }
    catch(err){
        return res.json({status:'error', error:';)'})
    }
    // console.log(user);
} )

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await userdb.findOne({username}).lean();
    if (!user) {
        return res.json({ status: "error", error: "Invalid username/password" });
    } else {
        if (await bcrypt.compare(password, user.password)) {
            //username and password found
            const token = jwt.sign({ id: user._id, username }, JWT_SECRET)
            return res.json({ status: "ok", data: token });
        }
    }
    res.json({ status: 'ok', data: "incorrect password" });

})

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || typeof username !== 'string') {
        return res.json({ status: 'error', error: 'Invalid Username' });
    }
    if (!password || typeof password !== 'string') {
        return res.json({ status: 'error', error: 'Invalid Password' });
    }
    const key = await bcrypt.hash(password, 10);
    const data = { username, password: key };
    console.log(data);
    try {
        const response = await userdb.create(data);
        console.log(response);
    }

    catch (err) {
        if (err.code === 11000) {
            return res.json({ status: 'error', error: 'username already used!!' })
        }
        else
            throw err;
    }
    console.log(data);
    res.json({ status: 'ok' });
})