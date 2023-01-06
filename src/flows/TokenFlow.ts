import * as qs from 'querystring'
import type { ClientOAuth2 } from '../ClientOAuth2'
import type { ClientOAuth2Token } from '../ClientOAuth2Token'
import { DEFAULT_URL_BASE } from '../constants'
import { createUri, getAuthError } from '../utils'

/**
 * Support implicit OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
 */
export class TokenFlow {
	constructor(private client: ClientOAuth2) {}

	/**
	 * Get the uri to redirect the user to for implicit authentication.
	 */
	getUri(opts?: any): string {
		const options = Object.assign({}, this.client.options, opts)
		return createUri(options, 'token')
	}

	/**
	 * Get the user access token from the uri.
	 */
	getToken(uri: string | URL, opts?: any): Promise<ClientOAuth2Token> {
		const options: any = Object.assign({}, this.client.options, opts)
		const url = typeof uri === 'object' ? uri : new URL(uri, DEFAULT_URL_BASE)
		const expectedUrl = new URL(options.redirectUri, DEFAULT_URL_BASE)

		if (
			typeof url.pathname === 'string' &&
			url.pathname !== expectedUrl.pathname
		) {
			return Promise.reject(
				new TypeError(
					'Redirected path should match configured path, but got: ' +
						url.pathname
				)
			)
		}

		// If no query string or fragment exists, we won't be able to parse
		// any useful information from the uri.
		if (!url.hash && !url.search) {
			return Promise.reject(new TypeError('Unable to process uri: ' + uri))
		}

		// Extract data from both the fragment and query string. The fragment is most
		// important, but the query string is also used because some OAuth 2.0
		// implementations (Instagram) have a bug where state is passed via query.
		const data = Object.assign(
			{},
			typeof url.search === 'string'
				? qs.parse(url.search.substring(1))
				: url.search || {},
			typeof url.hash === 'string'
				? qs.parse(url.hash.substring(1))
				: url.hash || {}
		)

		const err = getAuthError(data)

		// Check if the query string was populated with a known error.
		if (err) {
			return Promise.reject(err)
		}

		// Check whether the state matches.
		if (options.state != null && data.state !== options.state) {
			return Promise.reject(new TypeError('Invalid state: ' + data.state))
		}

		// Initialize a new token and return.
		return Promise.resolve(this.client.createToken(data as unknown as string))
	}
}
