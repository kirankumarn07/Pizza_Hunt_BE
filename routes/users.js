import express from 'express';
import bcrypt from "bcrypt";
import jwt  from 'jsonwebtoken';
import { genPassword, createUser, getUserByMail } from '../helper.js';
import {auth} from "../middlewares/auth.js"

const router = express.Router();


//SignUp 
router.post("/signup",async(req,res)=> {
    const {email,password} = req.body;
    console.log(email,password);

    //To set Email Pattern
    if(!/^[\w]{1,}[\w.+-]{0,}@[\w-]{2,}([.][a-zA-Z]{2,}|[.][\w-]{2,}[.][a-zA-Z]{2,})$/g.test(email)){
        res.status(400).send({error: "Invalid Email Pattern"})
        return;
    }

    const isUserExist = await getUserByMail(email)
    console.log(isUserExist);
    if(isUserExist){
        res.status(400).send({error: "Email already exists"})
        return;
    }

    //To set Password Pattern
    if(!/^(?=.*?[A-Z])(?=(.*[a-z]){1,})(?=(.*[\d]){1,})(?=(.*[\W]){1,})(?!.*\s).{8,}$/g.test(password)){
        res.status(400).send({error: "Invalid Password Pattern"})
        return;
    }
    const hashedPassword = await genPassword(password);
    const create = await createUser(email,hashedPassword);
    res.send({message: "Created Successfully"});
});



//Login
router.post("/login", async(req,res)=> {
    const{email,password} = req.body;
    console.log(email,password);
    
    const userFromDB = await getUserByMail(email);
    console.log(userFromDB);
    if(!userFromDB){
        res.status(400).send({error: "Invalid Email or Password"})
        return;
    }

    const storedDBPassword = userFromDB.password;
    //To compare entered password and DB password are same
    const isPasswordMatch = await bcrypt.compare(password,storedDBPassword);
    if(!isPasswordMatch){
        res.status(400).send({error: "Invalid Email or Password"})
        return;
    }
    
    const token = jwt.sign({id: userFromDB._id}, process.env.SECRET_KEY)
    res.send({message: "Login Successfully", token: token});
})






export const usersRouter = router;