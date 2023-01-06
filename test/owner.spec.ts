/* global describe, it, context */
import { expect } from 'chai'
import config from './support/config'
import { ClientOAuth2, ClientOAuth2Token } from '../src'

describe('owner', () => {
	const githubAuth = new ClientOAuth2({
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		accessTokenUri: config.accessTokenUri,
		authorizationGrants: ['owner'],
		scopes: 'notifications',
	})

	describe('#getToken', () => {
		it('should get the token on behalf of the user', () =>
			githubAuth.owner
				.getToken(config.username, config.password)
				.then((user) => {
					expect(user).to.an.instanceOf(ClientOAuth2Token)
					expect(user.accessToken).to.equal(config.accessToken)
					expect(user.tokenType).to.equal('bearer')
					expect(user.data.scope).to.equal('notifications')
				}))
		context('when scopes are undefined', () => {
			it('should not send scope to an auth server', () => {
				const scopelessAuth = new ClientOAuth2({
					clientId: config.clientId,
					clientSecret: config.clientSecret,
					accessTokenUri: config.accessTokenUri,
					authorizationGrants: ['owner'],
				})
				return scopelessAuth.owner
					.getToken(config.username, config.password)
					.then((user) => {
						expect(user).to.an.instanceOf(ClientOAuth2Token)
						expect(user.accessToken).to.equal(config.accessToken)
						expect(user.tokenType).to.equal('bearer')
						expect(user.data.scope).to.equal(undefined)
					})
			})
		})
		context('when scopes are an empty array', () => {
			it('should send empty scope string to an auth server', () => {
				const scopelessAuth = new ClientOAuth2({
					clientId: config.clientId,
					clientSecret: config.clientSecret,
					accessTokenUri: config.accessTokenUri,
					authorizationGrants: ['owner'],
					scopes: [],
				})
				return scopelessAuth.owner
					.getToken(config.username, config.password)
					.then((user) => {
						expect(user).to.an.instanceOf(ClientOAuth2Token)
						expect(user.accessToken).to.equal(config.accessToken)
						expect(user.tokenType).to.equal('bearer')
						expect(user.data.scope).to.equal('')
					})
			})
		})
		context('when scopes are an empty string', () => {
			it('should send empty scope string to an auth server', () => {
				const scopelessAuth = new ClientOAuth2({
					clientId: config.clientId,
					clientSecret: config.clientSecret,
					accessTokenUri: config.accessTokenUri,
					authorizationGrants: ['owner'],
					scopes: '',
				})
				return scopelessAuth.owner
					.getToken(config.username, config.password)
					.then((user) => {
						expect(user).to.an.instanceOf(ClientOAuth2Token)
						expect(user.accessToken).to.equal(config.accessToken)
						expect(user.tokenType).to.equal('bearer')
						expect(user.data.scope).to.equal('')
					})
			})
		})

		describe('#sign', () => {
			it('should be able to sign a standard request object', () =>
				githubAuth.owner
					.getToken(config.username, config.password)
					.then((token) => {
						const obj = token.sign({
							method: 'GET',
							url: 'http://api.github.com/user',
						})

						expect(obj.headers.Authorization).to.equal(
							`Bearer ${config.accessToken}`
						)
					}))
		})

		describe('#refresh', () => {
			it('should make a request to get a new access token', () =>
				githubAuth.owner
					.getToken(config.username, config.password)
					.then((token) => token.refresh())
					.then((token) => {
						expect(token).to.an.instanceOf(ClientOAuth2Token)
						expect(token.accessToken).to.equal(config.refreshAccessToken)
						expect(token.tokenType).to.equal('bearer')
					}))
		})
	})
})
