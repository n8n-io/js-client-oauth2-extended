/* global describe, it */
import { expect } from 'chai'

import config from './support/config'
import { ClientOAuth2, ClientOAuth2Token } from '../src'

describe('user', () => {
	const githubAuth = new ClientOAuth2({
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		accessTokenUri: config.accessTokenUri,
		authorizationUri: config.authorizationUri,
		authorizationGrants: ['code'],
		redirectUri: config.redirectUri,
		scopes: ['notifications'],
	})

	const user = githubAuth.createToken(
		config.accessToken,
		config.refreshToken,
		'bearer'
	)

	user.expiresIn(0)

	describe('#sign', () => {
		it('should be able to sign a standard request object', () => {
			const obj = user.sign({
				method: 'GET',
				url: 'http://api.github.com/user',
				headers: {
					accept: '*/*',
				},
			})

			expect(obj.headers.Authorization).to.equal(`Bearer ${config.accessToken}`)
		})
	})

	describe('#refresh', () => {
		it('should make a request to get a new access token', async () => {
			expect(user.accessToken).to.equal(config.accessToken)
			expect(user.tokenType).to.equal('bearer')

			const token = await user.refresh({ body: { test: true } })

			expect(token).to.an.instanceOf(ClientOAuth2Token)
			expect(token.accessToken).to.equal(config.testRefreshAccessToken)
			expect(token.tokenType).to.equal('bearer')
			expect(token.refreshToken).to.equal(config.refreshRefreshToken)
		})
	})

	describe('#expired', () => {
		it('should return false when token is not expired', () => {
			user.expiresIn(10)

			expect(user.expired()).to.be.equal(false)
		})

		it('should return true when token is expired', () => {
			user.expiresIn(-10)

			expect(user.expired()).to.be.equal(true)
		})
	})
})
