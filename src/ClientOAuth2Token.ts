import type {
	ClientOAuth2,
	ClientOAuth2Options,
	RequestOptions,
} from './ClientOAuth2'
import { auth, requestOptions } from './utils'
import { DEFAULT_HEADERS } from './constants'

interface TokenData {
	token_type?: string
	access_token: string
	refresh_token: string
	expires_in: string | number | Date
	scope?: string
}
/**
 * General purpose client token generator.
 */
export class ClientOAuth2Token {
	readonly tokenType?: string

	readonly accessToken: string

	readonly refreshToken: string

	expires: Date

	constructor(private client: ClientOAuth2, readonly data: TokenData) {
		this.tokenType = data.token_type && data.token_type.toLowerCase()
		this.accessToken = data.access_token
		this.refreshToken = data.refresh_token

		this.expiresIn(Number(data.expires_in))
	}

	/**
	 * Expire the token after some time.
	 */
	expiresIn(duration: number | Date): Date {
		if (typeof duration === 'number') {
			this.expires = new Date()
			this.expires.setSeconds(this.expires.getSeconds() + duration)
		} else if (duration instanceof Date) {
			this.expires = new Date(duration.getTime())
		} else {
			throw new TypeError('Unknown duration: ' + duration)
		}

		return this.expires
	}

	/**
	 * Sign a standardized request object with user authentication information.
	 */
	sign(requestObject: RequestOptions): RequestOptions {
		if (!this.accessToken) {
			throw new Error('Unable to sign without access token')
		}

		requestObject.headers = requestObject.headers || {}

		if (this.tokenType === 'bearer') {
			requestObject.headers.Authorization = 'Bearer ' + this.accessToken
		} else {
			const parts = requestObject.url.split('#')
			const token = 'access_token=' + this.accessToken
			const url = parts[0].replace(/[?&]access_token=[^&#]/, '')
			const fragment = parts[1] ? '#' + parts[1] : ''

			// Prepend the correct query string parameter to the url.
			requestObject.url =
				url + (url.indexOf('?') > -1 ? '&' : '?') + token + fragment

			// Attempt to avoid storing the url in proxies, since the access token
			// is exposed in the query parameters.
			requestObject.headers.Pragma = 'no-store'
			requestObject.headers['Cache-Control'] = 'no-store'
		}

		return requestObject
	}

	/**
	 * Refresh a user access token with the supplied token.
	 */
	async refresh(opts?: ClientOAuth2Options): Promise<ClientOAuth2Token> {
		const options = Object.assign({}, this.client.options, opts)

		if (!this.refreshToken) {
			return Promise.reject(new Error('No refresh token'))
		}

		const data = await this.client.request(
			requestOptions(
				{
					url: options.accessTokenUri,
					method: 'POST',
					headers: Object.assign({}, DEFAULT_HEADERS, {
						Authorization: auth(options.clientId, options.clientSecret),
					}),
					body: {
						refresh_token: this.refreshToken,
						grant_type: 'refresh_token',
					},
				},
				options
			)
		)
		return this.client.createToken(Object.assign({}, this.data, data))
	}

	/**
	 * Check whether the token has expired.
	 */
	expired(): boolean {
		return Date.now() > this.expires.getTime()
	}
}
