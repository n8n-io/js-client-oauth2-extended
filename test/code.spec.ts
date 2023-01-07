/* global describe, it, context */
import { expect } from 'chai'
import { ClientOAuth2, ClientOAuth2Token } from '../src'

const config = require('./support/config')

describe('code', () => {
	const uri = `/auth/callback?code=${config.code}&state=${config.state}`

	const githubAuth = new ClientOAuth2({
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		accessTokenUri: config.accessTokenUri,
		authorizationUri: config.authorizationUri,
		authorizationGrants: ['code'],
		redirectUri: config.redirectUri,
		scopes: ['notifications'],
	})

	describe('#getUri', () => {
		it('should return a valid uri', () => {
			expect(githubAuth.code.getUri()).to.equal(
				`${config.authorizationUri}?client_id=abc&` +
					`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
					`response_type=code&state=&scope=notifications`
			)
		})
		context('when scopes are undefined', () => {
			it('should not include scope in the uri', () => {
				const authWithoutScopes = new ClientOAuth2({
					clientId: config.clientId,
					clientSecret: config.clientSecret,
					accessTokenUri: config.accessTokenUri,
					authorizationUri: config.authorizationUri,
					authorizationGrants: ['code'],
					redirectUri: config.redirectUri,
				})
				expect(authWithoutScopes.code.getUri()).to.equal(
					`${config.authorizationUri}?client_id=abc&` +
						`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
						`response_type=code&state=`
				)
			})
		})
		it('should include empty scopes array as an empty string', () => {
			const authWithEmptyScopes = new ClientOAuth2({
				clientId: config.clientId,
				clientSecret: config.clientSecret,
				accessTokenUri: config.accessTokenUri,
				authorizationUri: config.authorizationUri,
				authorizationGrants: ['code'],
				redirectUri: config.redirectUri,
				scopes: [],
			})
			expect(authWithEmptyScopes.code.getUri()).to.equal(
				`${config.authorizationUri}?client_id=abc&` +
					`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
					`response_type=code&state=&scope=`
			)
		})
		it('should include empty scopes string as an empty string', () => {
			const authWithEmptyScopes = new ClientOAuth2({
				clientId: config.clientId,
				clientSecret: config.clientSecret,
				accessTokenUri: config.accessTokenUri,
				authorizationUri: config.authorizationUri,
				authorizationGrants: ['code'],
				redirectUri: config.redirectUri,
				scopes: [],
			})
			expect(authWithEmptyScopes.code.getUri()).to.equal(
				`${config.authorizationUri}?client_id=abc&` +
					`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
					`response_type=code&state=&scope=`
			)
		})
		context('when authorizationUri contains query parameters', () => {
			it('should preserve query string parameters', () => {
				const authWithParams = new ClientOAuth2({
					clientId: config.clientId,
					clientSecret: config.clientSecret,
					accessTokenUri: config.accessTokenUri,
					authorizationUri: `${config.authorizationUri}?bar=qux`,
					authorizationGrants: ['code'],
					redirectUri: config.redirectUri,
					scopes: ['notifications'],
				})
				expect(authWithParams.code.getUri()).to.equal(
					`${config.authorizationUri}?bar=qux&client_id=abc&` +
						`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
						`response_type=code&state=&scope=notifications`
				)
			})
		})
	})

	describe('#getToken', () => {
		it('should request the token', async () => {
			const user = await githubAuth.code.getToken(uri)
			expect(user).to.an.instanceOf(ClientOAuth2Token)
			expect(user.accessToken).to.equal(config.accessToken)
			expect(user.tokenType).to.equal('bearer')
		})

		it('should reject with auth errors', async () => {
			let errored = false

			try {
				await githubAuth.code.getToken(
					`${config.redirectUri}?error=invalid_request`
				)
			} catch (err) {
				errored = true

				expect(err.code).to.equal('EAUTH')
				expect(err.body.error).to.equal('invalid_request')
			}
			expect(errored).to.equal(true)
		})

		describe('#sign', () => {
			it('should be able to sign a standard request object', async () => {
				const token = await githubAuth.code.getToken(uri)
				const obj = token.sign({
					method: 'GET',
					url: 'http://api.github.com/user',
				})
				expect(obj.headers.Authorization).to.equal(
					`Bearer ${config.accessToken}`
				)
			})
		})

		describe('#refresh', () => {
			it('should make a request to get a new access token', async () => {
				const token = await githubAuth.code.getToken(uri, {
					state: config.state,
				})
				const token1 = await token.refresh()
				expect(token1).to.an.instanceOf(ClientOAuth2Token)
				expect(token1.accessToken).to.equal(config.refreshAccessToken)
				expect(token1.tokenType).to.equal('bearer')
			})
		})
	})
})
