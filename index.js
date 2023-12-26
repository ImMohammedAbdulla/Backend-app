// require('dotenv').config({path: "./env"})
import dotenv from "dotenv";
import express from "express";
import connectdb from "./db/index.js";

dotenv.config({
    path: "./env"
})
const app = express()

connectdb()
