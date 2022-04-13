const nodemailer = require('nodemailer')

const sendEmail = async(email, subject, text) => {
    try{
        const transporter = nodemailer.createTransport({
            service: process.env.SERVICE,
            auth:{
                user: process.env.user,
                pass: process.env.PASSWORD
            }
        })

        await transporter.sendMail({
            from: 'WYO App',
            to: email,
            subject: subject,
            text: text
        })

        
    } catch(error){
        console.log('email failed')
    }
}

module.exports = sendEmail