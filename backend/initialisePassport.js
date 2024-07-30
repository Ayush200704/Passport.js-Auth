import LocalStrategy from "passport-local"
LocalStrategy.Strategy
import bcrypt from "bcrypt"

export const initialisePassport = (passport, getUserByEmail, getUserById) => {
    const authenticateUser = async(email, password, done) => {
        const user = getUserByEmail(email)
        if(!user){
            return done(null, false, {message: "email was not found"})
        }
        try {
            if(await bcrypt.compare(password, user.password)){
                return done(null, user)
            }
            else{
                return done(null, false, {message: "password is incorrect"})
            }
        } catch (error) {
            return done(error)
        }
    }   
    passport.use(new LocalStrategy({usernameField: "email"}, authenticateUser))
    passport.serializeUser((user, done)=> done(null, user.id))
    passport.deserializeUser((id, done)=> done(null, getUserById(id)))
}