const express = require("express");
const path = require("path");
const mysql = require("mysql");
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');


dotenv.config({ path: __dirname + '/.env' });

const app = express();

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    port: '3307',
    database: process.env.DATABASE
});


const publicDirectory = path.join(__dirname, './public')
app.use(express.static(publicDirectory));


app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

//image part
app.use(fileUpload());



app.set('view engine', 'hbs');


db.connect((error) => {
    if (error) {
        console.log(error);
    } else {
        console.log("My sql connected...");
    }
})


//Define routes
app.use('/', require('./routes/pages'));
app.use('/auth', require('./routes/auth'));
// 404 page
app.use((req, res) => {
    res.status(404).render('404');
});



app.listen(5000, () => {
    console.log('Server started on port 5000');
});