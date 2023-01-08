import * as qs from 'querystring'
import type { ClientOAuth2, ClientOAuth2Options } from './ClientOAuth2'
import type { ClientOAuth2Token } from './ClientOAuth2Token'
import { DEFAULT_HEADERS, DEFAULT_URL_BASE } from './constants'
import {
	auth,
	expects,
	getAuthError,
	requestOptions,
	sanitizeScope,
} from './utils'

interface CodeFlowBody {
	code: string | string[]
	grant_type: 'authorization_code'
	redirect_uri?: string
	client_id?: string
}

/**
 * Support authorization code OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.1
 */
export class CodeFlow {
	constructor(private client: ClientOAuth2) {}

	/**
	 * Generate the uri for doing the first redirect.
	 */
	getUri(opts?: ClientOAuth2Options): string {
		const options = { ...this.client.options, ...opts }

		// Check the required parameters are set.
		expects(options, 'clientId', 'authorizationUri')

		const query: any = {
			client_id: options.clientId,
			redirect_uri: options.redirectUri,
			response_type: 'code',
			state: options.state,
		}
		if (options.scopes !== undefined) {
			query.scope = sanitizeScope(options.scopes)
		}

		const sep = options.authorizationUri.includes('?') ? '&' : '?'
		return (
			options.authorizationUri +
			sep +
			qs.stringify({ ...query, ...options.query })
		)
	}

	/**
	 * Get the code token from the redirected uri and make another request for
	 * the user access token.
	 */
	async getToken(
		uri?: string | URL,
		opts?: ClientOAuth2Options
	): Promise<ClientOAuth2Token> {
		const options = { ...this.client.options, ...opts }

		expects(options, 'clientId', 'accessTokenUri')

		const url = uri instanceof URL ? uri : new URL(uri, DEFAULT_URL_BASE)
		if (
			typeof options.redirectUri === 'string' &&
			typeof url.pathname === 'string' &&
			url.pathname !== new URL(options.redirectUri, DEFAULT_URL_BASE).pathname
		) {
			return Promise.reject(
				new TypeError(
					'Redirected path should match configured path, but got: ' +
						url.pathname
				)
			)
		}

		if (!url.search || !url.search.substring(1)) {
			return Promise.reject(new TypeError('Unable to process uri: ' + uri))
		}

		const data =
			typeof url.search === 'string'
				? qs.parse(url.search.substring(1))
				: url.search || {}
		const err = getAuthError(data)

		if (err) {
			return Promise.reject(err)
		}

		if (options.state != null && data.state !== options.state) {
			return Promise.reject(new TypeError('Invalid state: ' + data.state))
		}

		// Check whether the response code is set.
		if (!data.code) {
			return Promise.reject(
				new TypeError('Missing code, unable to request token')
			)
		}

		const headers = { ...DEFAULT_HEADERS }
		const body: CodeFlowBody = {
			code: data.code,
			grant_type: 'authorization_code',
			redirect_uri: options.redirectUri,
		}

		// `client_id`: REQUIRED, if the client is not authenticating with the
		// authorization server as described in Section 3.2.1.
		// Reference: https://tools.ietf.org/html/rfc6749#section-3.2.1
		if (options.clientSecret) {
			headers.Authorization = auth(options.clientId, options.clientSecret)
		} else {
			body.client_id = options.clientId
		}

		const responseData = await this.client.request(
			requestOptions(
				{
					url: options.accessTokenUri,
					method: 'POST',
					headers,
					body,
				},
				options
			)
		)
		return this.client.createToken(responseData)
	}
}
