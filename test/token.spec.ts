/* global describe, it, context */
import { expect } from 'chai'
import config from './support/config'
import { ClientOAuth2, ClientOAuth2Token } from '../src'

describe('token', () => {
	const uri = `${config.redirectUri}#access_token=${config.accessToken}&token_type=bearer`

	const githubAuth = new ClientOAuth2({
		clientId: config.clientId,
		authorizationUri: config.authorizationUri,
		authorizationGrants: ['token'],
		redirectUri: config.redirectUri,
		scopes: ['notifications'],
	})

	describe('#getUri', () => {
		it('should return a valid uri', () => {
			expect(githubAuth.token.getUri()).to.equal(
				`${config.authorizationUri}?client_id=abc&` +
					`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
					`response_type=token&state=&scope=notifications`
			)
		})
		context('when scopes are undefined', () => {
			it('should not include scope in the url', () => {
				const authWithoutScopes = new ClientOAuth2({
					clientId: config.clientId,
					authorizationUri: config.authorizationUri,
					authorizationGrants: ['token'],
					redirectUri: config.redirectUri,
				})
				expect(authWithoutScopes.token.getUri()).to.equal(
					`${config.authorizationUri}?client_id=abc&` +
						`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
						`response_type=token&state=`
				)
			})
		})
		it('should include empty scopes array as an empty string', () => {
			const authWithoutScopes = new ClientOAuth2({
				clientId: config.clientId,
				authorizationUri: config.authorizationUri,
				authorizationGrants: ['token'],
				redirectUri: config.redirectUri,
				scopes: [],
			})
			expect(authWithoutScopes.token.getUri()).to.equal(
				`${config.authorizationUri}?client_id=abc&` +
					`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
					`response_type=token&state=&scope=`
			)
		})
		it('should include empty scopes string as an empty string', () => {
			const authWithoutScopes = new ClientOAuth2({
				clientId: config.clientId,
				authorizationUri: config.authorizationUri,
				authorizationGrants: ['token'],
				redirectUri: config.redirectUri,
				scopes: '',
			})
			expect(authWithoutScopes.token.getUri()).to.equal(
				`${config.authorizationUri}?client_id=abc&` +
					`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
					`response_type=token&state=&scope=`
			)
		})

		context('when authorizationUri contains query parameters', () => {
			it('should preserve query string parameters', () => {
				const authWithParams = new ClientOAuth2({
					clientId: config.clientId,
					authorizationUri: `${config.authorizationUri}?bar=qux`,
					authorizationGrants: ['token'],
					redirectUri: config.redirectUri,
					scopes: ['notifications'],
				})
				expect(authWithParams.token.getUri()).to.equal(
					`${config.authorizationUri}?bar=qux&client_id=abc&` +
						`redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&` +
						`response_type=token&state=&scope=notifications`
				)
			})
		})
	})

	describe('#getToken', () => {
		it('should parse the token from the response', () =>
			githubAuth.token.getToken(uri).then((user) => {
				expect(user).to.an.instanceOf(ClientOAuth2Token)
				expect(user.accessToken).to.equal(config.accessToken)
				expect(user.tokenType).to.equal('bearer')
			}))

		describe('#sign', () => {
			it('should be able to sign a standard request object', () =>
				githubAuth.token.getToken(uri).then((token) => {
					const obj = token.sign({
						method: 'GET',
						url: 'http://api.github.com/user',
					})

					expect(obj.headers.Authorization).to.equal(
						`Bearer ${config.accessToken}`
					)
				}))
		})

		it('should fail if token not present', (done) => {
			githubAuth.token.getToken(config.redirectUri).then(
				() => done(new Error('Promise should fail')),
				() => done()
			)
		})
	})
})
