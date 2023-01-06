import * as qs from 'querystring'
import { fetch } from 'popsicle'
import { getAuthError } from './utils'
import { ClientOAuth2Token } from './ClientOAuth2Token'
import {
	CodeFlow,
	CredentialsFlow,
	JwtBearerFlow,
	OwnerFlow,
	TokenFlow,
} from './flows'

/**
 * Construct an object that can handle the multiple OAuth 2.0 flows.
 */
export class ClientOAuth2 {
	options: any

	code: CodeFlow

	token: TokenFlow

	owner: OwnerFlow

	credentials: CredentialsFlow

	jwt: JwtBearerFlow

	constructor(options: any) {
		this.options = options

		this.code = new CodeFlow(this)
		this.token = new TokenFlow(this)
		this.owner = new OwnerFlow(this)
		this.credentials = new CredentialsFlow(this)
		this.jwt = new JwtBearerFlow(this)
	}

	/**
	 * Create a new token from existing data.
	 */
	createToken(
		access?: string,
		refresh?: string,
		type?: string,
		data?: any
	): ClientOAuth2Token {
		const options = Object.assign(
			{},
			data,
			typeof access === 'string' ? { access_token: access } : access,
			typeof refresh === 'string' ? { refresh_token: refresh } : refresh,
			typeof type === 'string' ? { token_type: type } : type
		)

		return new ClientOAuth2Token(this, options)
	}

	/**
	 * Attempt to parse response body as JSON, fall back to parsing as a query string.
	 */
	private parseResponseBody(body: string) {
		try {
			return JSON.parse(body)
		} catch (e) {
			return qs.parse(body)
		}
	}

	/**
	 * Using the built-in request method, we'll automatically attempt to parse
	 * the response.
	 */
	async request(options: any): Promise<any> {
		let url = options.url
		const query = qs.stringify(options.query)

		if (query) {
			url += (url.indexOf('?') === -1 ? '?' : '&') + query
		}

		const response = await fetch(url, {
			body: qs.stringify(options.body),
			method: options.method,
			headers: options.headers,
		})
		const responseBody = await response.text()

		const body = this.parseResponseBody(responseBody)
		const authErr = getAuthError(body)

		if (authErr) {
			return Promise.reject(authErr)
		}

		if (response.status < 200 || response.status >= 399) {
			const statusErr = new Error('HTTP status ' + response.status) as any
			statusErr.status = response.status
			statusErr.body = responseBody
			statusErr.code = 'ESTATUS'
			return Promise.reject(statusErr)
		}

		return body
	}
}
