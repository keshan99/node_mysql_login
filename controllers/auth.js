const mysql = require("mysql");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { promisify } = require('util');


const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE,
    port: '3307',

});


db.connect((error) => {
    if (error) {
        console.log(error);
    } else {
        console.log("My sql connected.sss..");
    }
})


exports.login = async(req, res) => {
    try {

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).render('login', {
                message: 'Please provide an email and passsword'
            })
        }

        db.query('SELECT * FROM users WHERE email = ?', [email], async(error, results) => {
            console.log(results);
            if (results.length == 0) {
                res.status(401).render('login', {
                    message: 'Email is incorrect'
                })
            } else if (!(await bcrypt.compare(password, results[0].password))) {
                res.status(401).render('login', {
                    message: 'password is incorrect'
                })
            } else {
                const id = results[0].id;

                const token = jwt.sign({ id: id }, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN
                });

                console.log('the token is: ' + token);

                const cookieOptions = {
                    expires: new Date(
                        Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                    ),
                    httpOnly: true
                }

                res.cookie('jwt', token, cookieOptions);
                res.status(200).redirect("/");



            }




        })


    } catch (error) {
        console.log(error);
    }
}


exports.register = (req, res) => {
    console.log(req.files);

    //const name = res.body.name;
    //const email = res.body.email;
    //const password = res.body.password;
    //const passwordConform = res.body.passwordConform;
    const { name, email, password, passwordConform } = req.body;
    //console.log(req);
    //Todo: add img part
    if (!req.files) {
        return res.render('register', {
            message: 'No files were uploaded.'
        })
    }

    var file = req.files.user_img;
    var img_name = name + file.name;

    if (file.mimetype == "image/jpeg" || file.mimetype == "image/png" || file.mimetype == "image/gif") {
        file.mv('../NODE_MYSQL/public/images/upload/' + img_name, function(err) {
            if (err)
                return res.status(500).send(err);

            //var sql = "INSERT INTO `users_image`(`first_name`,`last_name`,`mob_no`,`user_name`, `password` ,`image`) VALUES ('" + fname + "','" + lname + "','" + mob + "','" + name + "','" + pass + "','" + img_name + "')";

            //         var query = db.query(sql, function(err, result) {
            //              res.redirect('profile/'+result.insertId);
            //         });
        });
    } else {
        return res.render('register', {
            message: "This format is not allowed , please upload file with '.png','.gif','.jpg'"
        })
    }


    // TODO: add img part    end

    db.query('SELECT email FROM users WHERE email = ?', [email], async(error, result) => {
        if (error) {
            console.log(error);
        }

        if (result.length > 0) {
            return res.render('register', {
                message: 'That email is already in use'
            })
        } else if (password !== passwordConform) {
            return res.render('register', {
                message: 'Password do not match'
            });
        }

        let hashedPassword = await bcrypt.hash(password, 8);
        console.log(hashedPassword);



        db.query('INSERT INTO users SET ?', { name: name, email: email, password: hashedPassword, user_img: img_name }, (errror, result) => {
            if (error) {
                console.log(error);
            } else {
                console.log(result);
                return res.render('login');

                // return res.render('register', {
                //    message: 'User registered'
                // });
            }
        })

    });

    //res.send("Form submited...");

}

exports.isLoggedIn = async(req, res, next) => {
    if (req.cookies.jwt) {
        try {
            // TODO: verify the token
            const decoed = await promisify(jwt.verify)(req.cookies.jwt,
                process.env.JWT_SECRET)

            console.log(decoed);

            // TODO: cheak if still exists
            db.query('SELECT * FROM users WHERE id = ?', [decoed.id], (error, result) => {
                console.log(result);

                if (!result) {
                    return next();
                }

                // create user variable
                req.user = result[0]
                return next();
            })

        } catch (error) {
            console.log(error);
            return next();
        }
    } else {
        return next();
    }

}

exports.logout = async(req, res) => {
    res.cookie('jwt', 'logout', {
        expires: new Date(Date.now() + 2 * 1000),
        httpOnly: true
    })

    res.status(200).redirect('/')
}