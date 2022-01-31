const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());

let refreshTokens=[]

const users = [
    {
        id: "1",
        username: 'John',
        password: "john123",
        isAdmin: true
    },
    {
        id: "2",
        username: 'Mari',
        password: "mari123",
        isAdmin: true
    }

]

const verify = (req, res, next) => {
    const authHeader = req.headers.authorization
    if(authHeader){
        const token=authHeader.split(" ")[0]
        jwt.verify(token,"supersecretkey",(err,user)=>{
            if(err){
                res.status(403).json('token is not valid')
            }

            req.user = user;
            next();
        })

    }else{
        res.status(401).json("you not authorizate")
    }
}

const generateToken =(user)=>{

   return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "supersecretkey",{expiresIn:"20s"})

}
const generateRefreshToken =(user)=>{
    
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "refreshKey")

}


app.post('/api/login', (req, res) => {
    const { username, password } = req.body
    const user = users.find((u) => {
        return u.username === username && u.password === password
    })
    if (user) {

        const  accessToken = generateToken(user)
        const  refreshToken =generateRefreshToken(user)
        refreshTokens.push(refreshToken)  

        res.status(200).json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken:accessToken,
            refreshToken:refreshToken

        })
    } else {
        res.status(400).json('incorect pasword or username')
    }
})


app.post("/api/refresh",(req,res)=>{
    const refreshToken=req.body.token

    if(!refreshToken){
        res.status(401).json('not authenticated')
    }

    if(!refreshTokens.includes(refreshToken)){
        res.status(403).json('Refresh token is not valid')
    }
    jwt.verify(refreshToken,"refreshKey",(err,user)=>{
        err && res.status(401).json(err)
        refreshTokens=refreshTokens.filter(r=>r !==refreshToken)
        const newAccesToken = generateToken(user)
        const newRefreshToken = generateRefreshToken(user)
        refreshTokens.push(newRefreshToken)
        res.status(200).json({
            accessToken:newAccesToken,
            refreshToken:newRefreshToken
        })
    })
})



app.delete('/api/user/:userId',verify,(req,res)=>{
    if(req.user.id===req.params.userId && req.user.isAdmin ){
        res.status(200).json("user has been deleted")

    }else{
        res.status(400).json("not allowed delete this user")
    }

})

app.post('/api/logout',verify,(req,res)=>{
    const refreshToken=req.body.refreshToken
    refreshTokens=refreshTokens.filter(token=>token!==refreshToken)
    res.status(200).json("logout succesfuly")

})

app.listen(5000, () => console.log("Backend server is running!"));
