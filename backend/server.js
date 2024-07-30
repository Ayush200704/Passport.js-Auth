import dotenv from 'dotenv'
if (process.env.NODE_ENV !== "production") {
    dotenv.config()
}

import express from "express"
import bcrypt from "bcrypt"
import passport from "passport"
import session from "express-session"
import flash from "express-flash"
import {initialisePassport} from "./initialisePassport.js"
import methodOverride from "method-override"

const app = express()

app.set("view-engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(flash())
app.use(passport.initialize())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.session())
app.use(methodOverride("_method"))
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    next();
});


const users = [];

initialisePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id )
)




app.get("/", checkIsAuthenticate, (req, res) => {
    res.render("index.ejs", { name: "Ayush" })
})

app.get("/register", checkNotAuthenticate, (req, res) => {
    res.render("register.ejs")
})

app.get("/login", checkNotAuthenticate, (req, res) => {
    res.render("login.ejs")
})

app.post("/register", checkNotAuthenticate, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        res.redirect("/login")
    } catch (error) {
        console.log(error.message)
        res.redirect("/register")
    }
})

app.post("/login", checkNotAuthenticate, passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
}))

app.delete("/logout", (req, res)=>{
    req.logout((err)=>{
        if(err){
            return next(err)
        }
        res.clearCookie('connect.sid')
        res.redirect("/login")
    });
    
})

function checkIsAuthenticate(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }
    res.redirect("/login")
}

function checkNotAuthenticate(req, res, next){
    if(req.isAuthenticated()){
        res.redirect("/")
    }
    next()
}


app.listen(5000, () => {
    console.log("listening to port 5000");
})



