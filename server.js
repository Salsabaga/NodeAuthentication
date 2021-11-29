require("dotenv").config();
const express = require("express");
const flash = require("connect-flash");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/client", express.static("client"));
app.use(flash());

app.use(
	session({
		secret: process.env.SECRET,
		resave: false,
		saveUninitialized: true,
		cookie: { maxAge: 1000 * 60 * 60 * 24 },
	})
);

app.use(passport.initialize());
app.use(passport.session());

app.use(function (req, res, next) {
	res.locals.error = req.flash("error");
	next();
});

const mongo_uri = `mongodb+srv://admin-danny:${process.env.MONGO_PASS}@loginuserscluster.tjyzo.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`;

mongoose.connect(mongo_uri);

const userSchema = new mongoose.Schema({
	username: String,
	email: String,
	hash: String,
	salt: String,
	admin: Boolean,
});

const User = mongoose.model("User", userSchema);

app.set("view engine", "ejs");

// Passport Config

function genPassword(password) {
	const salt = bcrypt.genSaltSync(10);
	const genHash = bcrypt.hashSync(password, salt);

	return {
		salt: salt,
		hash: genHash,
	};
}

function verifyPassword(password, hash, salt) {
	const hashVerify = bcrypt.hashSync(password, salt);
	return hash === hashVerify;
}

function verifyCallback(username, password, done) {
	User.findOne({ username: username }, function (err, user) {
		if (err) return done(err);
		if (!user) {
			return done(null, false, { message: "Username is not found" });
		}
		const isValid = verifyPassword(password, user.hash, user.salt);

		if (!isValid) {
			return done(null, false, { message: "Incorrect Password" });
		} else {
			return done(null, user);
		}
	});
}

passport.use(new LocalStrategy(verifyCallback));

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

// Routes

function isAuth(req, res, next) {
	if (req.isAuthenticated()) {
		res.redirect("/profile");
		return;
	}
	next();
}

app.get("/", (req, res) => {
	res.render("index");
});

app.get("/login", isAuth, (req, res) => {
	res.render("login");
});

app.post(
	"/login",
	passport.authenticate("local", {
		failureRedirect: "/login",
		failureFlash: true,
	}),
	(req, res) => {
		res.redirect("/profile");
	}
);

app.get("/register", (req, res) => {
	res.render("register");
});

app.post("/register", (req, res) => {
	const { username, password, password2, email, confirm } = req.body;
	let errors = [];
	User.findOne({ email: email }, function (err, user) {
		if (user) {
			errors.push({ msg: "E-mail is already registered" });
		}

		if (password.length < 6) {
			errors.push({ msg: "Password must be more than six characters." });
		}
		if (password !== password2) {
			errors.push({ msg: "Passwords do not match" });
		}
		if (!confirm) {
			errors.push({
				msg: "You must agree to terms and conditions to continue",
			});
		}
		if (!username || !email) {
			errors = [];
			errors.push({ msg: "Please enter your credentials to sign up" });
		}
		if (errors.length > 0) {
			res.render("register", { errors, username, password, password2, email });
		} else {
			const saltHash = genPassword(password);
			const salt = saltHash.salt;
			const hash = saltHash.hash;
			const newUser = new User({
				username: username,
				email: email,
				salt: salt,
				hash: hash,
				admin: false,
			});

			newUser
				.save()
				.then((user) => {
					console.log(user);
					req.login(user, (err) => {
						if (err) {
							return next(err);
						}
						return res.redirect("/profile");
					});
				})
				.catch((err) => {
					console.log(err);
				});
		}
	});
});

app.get("/logout", (req, res) => {
	req.logOut();
	res.redirect("/");
});

app.get("/profile", (req, res) => {
	if (req.isAuthenticated()) {
		res.render("profile", { loggedInUser: req.user.username });
	} else {
		res.send("<h2>Hey, what are you doing? What are you actually doing?</h2>");
	}
});

app.listen(3000, () => {
	console.log("Server is listening");
});
