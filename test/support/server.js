const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const assert = require('assert')
const Querystring = require('querystring')
const config = require('./config')
const app = express()

const credentials =
	'Basic ' +
	Buffer.from(config.clientId + ':' + config.clientSecret).toString('base64')

app.options('/login/oauth/access_token', cors())

app.post(
	'/login/oauth/access_token',
	cors(),
	bodyParser.urlencoded({ extended: false }),
	function (req, res) {
		const grantType = req.body.grant_type

		// Typically required header when parsing bodies.
		assert.strictEqual(typeof req.headers['content-length'], 'string')

		if (grantType === 'refresh_token') {
			assert.strictEqual(req.body.refresh_token, config.refreshToken)
			assert.strictEqual(req.headers.authorization, credentials)

			return res.send(
				Querystring.stringify({
					access_token: req.body.test
						? config.testRefreshAccessToken
						: config.refreshAccessToken,
					refresh_token: config.refreshRefreshToken,
					expires_in: 3000,
				})
			)
		}

		if (grantType === 'authorization_code') {
			assert.strictEqual(req.body.code, config.code)
			assert.strictEqual(req.headers.authorization, credentials)
		} else if (grantType === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
			assert.strictEqual(req.body.assertion, config.jwt)
			assert.strictEqual(req.headers.authorization, credentials)
		} else if (grantType === 'password') {
			assert.strictEqual(req.body.username, config.username)
			assert.strictEqual(req.body.password, config.password)
			assert.strictEqual(req.headers.authorization, credentials)
		} else {
			assert.strictEqual(grantType, 'client_credentials')
			assert.strictEqual(req.headers.authorization, credentials)
		}

		return res.json({
			access_token: config.accessToken,
			refresh_token: config.refreshToken,
			token_type: 'bearer',
			scope: req.body.scope,
		})
	}
)

app.listen(process.env.PORT || 7357)
