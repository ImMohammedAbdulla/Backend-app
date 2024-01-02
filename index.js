// require('dotenv').config({path: "./env"})
import dotenv from "dotenv";
import connectdb from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
    path: "./.env"
})

connectdb()
.then(() => {
    app.listen(process.env.PORT || 8000 , ()=>{
        console.log(`App is listening on port number ${process.env.PORT}`)
    })
})
.catch((err) => {
    console.log("Error occurred",err)
})