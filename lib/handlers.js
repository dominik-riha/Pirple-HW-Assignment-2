/*
 * Request Handlers
 *
 */

// Dependencies
var _data = require('./data');
var helpers = require('./helpers');
var config = require('./config');

// Define all the handlers
var handlers = {};

// Ping
handlers.ping = function (data, callback) {
	setTimeout(function () {
		callback(200);
	}, 5000);

};

// Not-Found
handlers.notFound = function (data, callback) {
	callback(404);
};

// Users
handlers.users = function (data, callback) {
	var acceptableMethods = ['post', 'get', 'put', 'delete'];
	if (acceptableMethods.indexOf(data.method) > -1) {
		handlers._users[data.method](data, callback);
	} else {
		callback(405);
	}
};

// Container for all the users methods
handlers._users = {};

// Users - post
// Required data: firstName, lastName, email, password, address
// Optional data: none
handlers._users.post = function (data, callback) {
	// Check that all required fields are filled out
	var firstName = typeof (data.payload.firstName) == 'string' && data.payload.firstName.trim().length > 0 ? data.payload.firstName.trim() : false;
	var lastName = typeof (data.payload.lastName) == 'string' && data.payload.lastName.trim().length > 0 ? data.payload.lastName.trim() : false;
	var email = typeof (data.payload.email) == 'string' && data.payload.email.trim().length > 0 ? data.payload.email.trim() : false;
	var password = typeof (data.payload.password) == 'string' && data.payload.password.trim().length > 0 ? data.payload.password.trim() : false;
	var address = typeof (data.payload.address) == 'string' && data.payload.address.trim().length > 0 ? data.payload.address.trim() : false;

	if (firstName && lastName && email && password && address) {
		// Make sure the user doesnt already exist
		_data.read('users', email, function (err, data) {
			if (err) {
				// Hash the password
				var hashedPassword = helpers.hash(password);

				// Create the user object
				if (hashedPassword) {
					var userObject = {
						'firstName': firstName,
						'lastName': lastName,
						'email': email,
						'hashedPassword': hashedPassword,
						'address': address
					};

					// Store the user
					_data.create('users', email, userObject, function (err) {
						if (!err) {
							callback(200);
						} else {
							callback(500, {'Error': 'Could not create the new user'});
						}
					});
				} else {
					callback(500, {'Error': 'Could not hash the user\'s password.'});
				}

			} else {
				// User alread exists
				callback(400, {'Error': 'A user with that email already exists'});
			}
		});

	} else {
		callback(400, {'Error': 'Missing required fields'});
	}

};

// Required data: email
// Optional data: none
handlers._users.get = function (data, callback) {
	// Check that email is valid
	var email = typeof (data.queryStringObject.email) == 'string' && data.queryStringObject.email.trim().length > 0 ? data.queryStringObject.email.trim() : false;
	if (email) {

		// Get token from headers
		var token = typeof (data.headers.token) == 'string' ? data.headers.token : false;
		// Verify that the given token is valid for the email
		handlers._tokens.verifyToken(token, email, function (tokenIsValid) {
			if (tokenIsValid) {
				// Lookup the user
				_data.read('users', email, function (err, data) {
					if (!err && data) {
						// Remove the hashed password from the user user object before returning it to the requester
						delete data.hashedPassword;
						callback(200, data);
					} else {
						callback(404);
					}
				});
			} else {
				callback(403, {"Error": "Missing required token in header, or token is invalid."})
			}
		});
	} else {
		callback(400, {'Error': 'Missing required field'})
	}
};

// Required data: email
// Optional data: firstName, lastName, password, address (at least one must be specified)
handlers._users.put = function (data, callback) {
	// Check for required field
	var email = typeof (data.payload.email) == 'string' && data.payload.email.trim().length > 0 ? data.payload.email.trim() : false;

	// Check for optional fields
	var firstName = typeof (data.payload.firstName) == 'string' && data.payload.firstName.trim().length > 0 ? data.payload.firstName.trim() : false;
	var lastName = typeof (data.payload.lastName) == 'string' && data.payload.lastName.trim().length > 0 ? data.payload.lastName.trim() : false;
	var password = typeof (data.payload.password) == 'string' && data.payload.password.trim().length > 0 ? data.payload.password.trim() : false;
	var address = typeof (data.payload.address) == 'string' && data.payload.address.trim().length > 0 ? data.payload.address.trim() : false;

	// Error if email is invalid
	if (email) {
		// Error if nothing is sent to update
		if (firstName || lastName || password || address) {

			// Get token from headers
			var token = typeof (data.headers.token) == 'string' ? data.headers.token : false;

			// Verify that the given token is valid for the email
			handlers._tokens.verifyToken(token, email, function (tokenIsValid) {
				if (tokenIsValid) {

					// Lookup the user
					_data.read('users', email, function (err, userData) {
						if (!err && userData) {
							// Update the fields if necessary
							if (firstName) {
								userData.firstName = firstName;
							}
							if (lastName) {
								userData.lastName = lastName;
							}
							if (password) {
								userData.hashedPassword = helpers.hash(password);
							}
							if (address) {
								userData.address = address;
							}
							// Store the new updates
							_data.update('users', email, userData, function (err) {
								if (!err) {
									callback(200);
								} else {
									callback(500, {'Error': 'Could not update the user.'});
								}
							});
						} else {
							callback(400, {'Error': 'Specified user does not exist.'});
						}
					});
				} else {
					callback(403, {"Error": "Missing required token in header, or token is invalid."});
				}
			});
		} else {
			callback(400, {'Error': 'Missing fields to update.'});
		}
	} else {
		callback(400, {'Error': 'Missing required field.'});
	}

};

// Required data: email
// Cleanup old checks associated with the user
handlers._users.delete = function (data, callback) {
	// Check that email is valid
	var email = typeof (data.queryStringObject.email) == 'string' && data.queryStringObject.email.trim().length > 0 ? data.queryStringObject.email.trim() : false;
	if (email) {

		// Get token from headers
		var token = typeof (data.headers.token) == 'string' ? data.headers.token : false;

		// Verify that the given token is valid for the email
		handlers._tokens.verifyToken(token, email, function (tokenIsValid) {
			if (tokenIsValid) {
				// Lookup the user
				_data.read('users', email, function (err, userData) {
					if (!err && userData) {
						// Delete the user's data
						_data.delete('users', email, function (err) {
							if (!err) {
								callback(200);
							} else {
								callback(500, {'Error': 'Could not delete the specified user'});
							}
						});
					} else {
						callback(400, {'Error': 'Could not find the specified user.'});
					}
				});
			} else {
				callback(403, {"Error": "Missing required token in header, or token is invalid."});
			}
		});
	} else {
		callback(400, {'Error': 'Missing required field'})
	}
};

// Tokens
handlers.tokens = function (data, callback) {
	var acceptableMethods = ['post', 'get', 'put', 'delete'];
	if (acceptableMethods.indexOf(data.method) > -1) {
		handlers._tokens[data.method](data, callback);
	} else {
		callback(405);
	}
};

// Container for all the tokens methods
handlers._tokens = {};

// Tokens - post
// Required data: email, password
// Optional data: none
handlers._tokens.post = function (data, callback) {
	var email = typeof (data.payload.email) == 'string' && data.payload.email.trim().length > 0 ? data.payload.email.trim() : false;
	var password = typeof (data.payload.password) == 'string' && data.payload.password.trim().length > 0 ? data.payload.password.trim() : false;
	if (email && password) {
		// Lookup the user who matches that email
		_data.read('users', email, function (err, userData) {
			if (!err && userData) {
				// Hash the sent password, and compare it to the password stored in the user object
				var hashedPassword = helpers.hash(password);
				if (hashedPassword === userData.hashedPassword) {
					// If valid, create a new token with a random name. Set an expiration date 1 hour in the future.
					var tokenId = helpers.createRandomString(20);
					var expires = Date.now() + 1000 * 60 * 60;
					var tokenObject = {
						'email': email,
						'id': tokenId,
						'expires': expires
					};

					// Store the token
					_data.create('tokens', tokenId, tokenObject, function (err) {
						if (!err) {
							callback(200, tokenObject);
						} else {
							callback(500, {'Error': 'Could not create the new token'});
						}
					});
				} else {
					callback(400, {'Error': 'Password did not match the specified user\'s stored password'});
				}
			} else {
				callback(400, {'Error': 'Could not find the specified user.'});
			}
		});
	} else {
		callback(400, {'Error': 'Missing required field(s).'})
	}
};

// Tokens - get
// Required data: id
// Optional data: none
handlers._tokens.get = function (data, callback) {
	// Check that id is valid
	var id = typeof (data.queryStringObject.id) == 'string' && data.queryStringObject.id.trim().length === 20 ? data.queryStringObject.id.trim() : false;
	if (id) {
		// Lookup the token
		_data.read('tokens', id, function (err, tokenData) {
			if (!err && tokenData) {
				callback(200, tokenData);
			} else {
				callback(404);
			}
		});
	} else {
		callback(400, {'Error': 'Missing required field, or field invalid'})
	}
};

// Tokens - put
// Required data: id, extend
// Optional data: none
handlers._tokens.put = function (data, callback) {
	var id = typeof (data.payload.id) == 'string' && data.payload.id.trim().length === 20 ? data.payload.id.trim() : false;
	var extend = typeof (data.payload.extend) == 'boolean' && data.payload.extend;
	if (id && extend) {
		// Lookup the existing token
		_data.read('tokens', id, function (err, tokenData) {
			if (!err && tokenData) {
				// Check to make sure the token isn't already expired
				if (tokenData.expires > Date.now()) {
					// Set the expiration an hour from now
					tokenData.expires = Date.now() + 1000 * 60 * 60;
					// Store the new updates
					_data.update('tokens', id, tokenData, function (err) {
						if (!err) {
							callback(200);
						} else {
							callback(500, {'Error': 'Could not update the token\'s expiration.'});
						}
					});
				} else {
					callback(400, {"Error": "The token has already expired, and cannot be extended."});
				}
			} else {
				callback(400, {'Error': 'Specified user does not exist.'});
			}
		});
	} else {
		callback(400, {"Error": "Missing required field(s) or field(s) are invalid."});
	}
};


// Tokens - delete
// Required data: id
// Optional data: none
handlers._tokens.delete = function (data, callback) {
	// Check that id is valid
	var id = typeof (data.queryStringObject.id) == 'string' && data.queryStringObject.id.trim().length === 20 ? data.queryStringObject.id.trim() : false;
	if (id) {
		// Lookup the token
		_data.read('tokens', id, function (err, tokenData) {
			if (!err && tokenData) {
				// Delete the token
				_data.delete('tokens', id, function (err) {
					if (!err) {
						callback(200);
					} else {
						callback(500, {'Error': 'Could not delete the specified token'});
					}
				});
			} else {
				callback(400, {'Error': 'Could not find the specified token.'});
			}
		});
	} else {
		callback(400, {'Error': 'Missing required field'})
	}
};

// Verify if a given token id is currently valid for a given user
handlers._tokens.verifyToken = function (id, email, callback) {
	// Lookup the token
	_data.read('tokens', id, function (err, tokenData) {
		if (!err && tokenData) {
			// Check that the token is for the given user and has not expired
			if (tokenData.email === email && tokenData.expires > Date.now()) {
				callback(true);
			} else {
				callback(false);
			}
		} else {
			callback(false);
		}
	});
};

// Validate that a given token is valid (regardless of the user)
handlers._tokens.validateToken = function (id, callback) {
	// Lookup the token
	_data.read('tokens', id, function (err, tokenData) {
		if (!err && tokenData) {
			// Check that the token is for the given user and has not expired
			if (tokenData.expires > Date.now()) {
				callback(true);
			} else {
				callback(false);
			}
		} else {
			callback(false);
		}
	});
}

// Menu
handlers.menu = function (data, callback) {
	var acceptableMethods = ['get'];
	if (acceptableMethods.indexOf(data.method) > -1) {
		handlers._menu[data.method](data, callback);
	} else {
		callback(405);
	}
};

// Container for all the menu methods
handlers._menu = {};

// Menu - get
// Required data: none
// Optional data: none
handlers._menu.get = function (data, callback) {
	// Get token from headers
	var token = typeof (data.headers.token) == 'string' ? data.headers.token : false;
	// Verify that the given token is valid for the email
	handlers._tokens.validateToken(token, function (tokenIsValid) {
		if (tokenIsValid) {
			callback(200, config.menu);
		} else {
			callback(403, {"Error": "Missing required token in header, or token is invalid."})
		}
	});
};


// Export the handlers
module.exports = handlers;
