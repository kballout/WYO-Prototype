# WYO-Prototype

A backend server made with Node JS and MongoDB that contains basic login, logout, and sign up functionality. After cloning
the repository and installing all dependencies, create a .env file with the following variables.

1. MONGO_URI = Your MongoDB URI followed by /loginapi. loginapi is the name of the database that connects to the Node server. If you're 
using it on localhost the URI will simply be mongoDB://127.0.0.1:27017/loginapi

2. SERVICE = The service you're using for nodemailer. In my case it's just gmail

3. USER = The email address being used for nodemailer

4. PASSWORD = The password for the email address used for nodemailer

5. ACCESS_TOKEN = The secret key used for the JWT access token. This could be anything or randomly generated

6. REFRESH_TOKEN = Same deal as the ACCESS_TOKEN

7. ACCESS_TOKEN_EXP = Expiration time for the access token. e.g. '10s'

8. REFRESH_TOKEN_EXP = Expiration time for the refresh token. e.g. '30d'
