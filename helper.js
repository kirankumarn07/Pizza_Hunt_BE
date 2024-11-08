import { client } from "./index.js";
import bcrypt from "bcrypt";


export async function genPassword(password){
    const salt = await bcrypt.genSalt(10);
    console.log(salt);
    const hashedPassword = await bcrypt.hash(password,salt);
    console.log(hashedPassword);
    return hashedPassword;

}
// console.log(genPassword("password"));


export async function  createUser(email,hashedPassword){
    return await client
      .db("Pizza-Hunt")
      .collection("users")
      .insertOne({email: email, password: hashedPassword})
      
}

export async function getUserByMail(email){
    return await client
      .db("Pizza-Hunt")
      .collection("users")
      .findOne({email: email}); 
}