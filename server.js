const express = require('express')
const app = express();
const dotenv = require('dotenv')
dotenv.config()
const mongoose = require('mongoose')

//Import Routes
const authRoute = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboardRoutes')


//Route Middlewares
app.use(express.json())
app.use('/api/user', authRoute);
app.use('/api/posts', dashboardRoutes);

app.listen(3000, () => console.log('Server UP and running'));


//connect db
mongoose.connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    }).then(console.log('connected to db'))

app.listen(3001, () => {
    console.log('server is running on port 3001')
})
