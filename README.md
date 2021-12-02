# Node Authentication with Passport.js

## Description

A simple application that includes a welcome page, and allows user authentication. When authenticated, it will enable sessions to ensure that the user is not logged out should a tab close and reopen. A simple login and registration form is provided and includes error handling based on the user input.

Passport.js enables the security and authentication I need for this application and future applications that would require user authentication. Using the most common strategy, LocalStrategy, by using a username/email and password combination has shown me the structure of how a login procedure would work via the configuration.

```js
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
```

Encryption utilising the [bcrypt](https://www.npmjs.com/package/bcrypt) module, ensuring that a password saved to a database is fully **salted and hashed**, and utilising Decryption whenever a user wishes to login, with independent error handling should a username not exist or if a password is incorrect. This is achieved by using the [Connect-flash](https://www.npmjs.com/package/connect-flash) module and using its middleware globally to effectively notify the user for any login errors on the front-end.

### SCSS

Utilising SCSS has been a useful tool for handling so much repetitive CSS in my layouts, the use of mixins has made styling the login and registration forms that have similar layouts but the latter having more elements.

```scss
@mixin inputArea {
	display: flex;
	flex-direction: column;
	justify-content: space-evenly;
	align-items: center;
	width: 60%;
	max-height: 100vh;
}

@mixin formArea($w) {
	display: flex;
	flex-direction: column;
	width: $w;
}
```

### The Future

Another aspect I would need to add would be responsive layout for the application, especially when using SVGs which is another field of difficulty yet I am able to research and apply to many more projects with a more creative UI layout.
