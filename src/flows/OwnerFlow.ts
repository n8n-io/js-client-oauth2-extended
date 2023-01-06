import type { ClientOAuth2 } from '../ClientOAuth2'
import type { ClientOAuth2Token } from '../ClientOAuth2Token'
import { DEFAULT_HEADERS } from '../constants'
import { auth, requestOptions, sanitizeScope } from '../utils'

/**
 * Support resource owner password credentials OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.3
 */
export class OwnerFlow {
	constructor(private client: ClientOAuth2) {}

	/**
	 * Make a request on behalf of the user credentials to get an access token.
	 */
	async getToken(
		username: string,
		password: string,
		opts?: any
	): Promise<ClientOAuth2Token> {
		const options: any = Object.assign({}, this.client.options, opts)

		const body: any = {
			username: username,
			password: password,
			grant_type: 'password',
		}
		if (options.scopes !== undefined) {
			body.scope = sanitizeScope(options.scopes)
		}

		const data = await this.client.request(
			requestOptions(
				{
					url: options.accessTokenUri,
					method: 'POST',
					headers: Object.assign({}, DEFAULT_HEADERS, {
						Authorization: auth(options.clientId, options.clientSecret),
					}),
					body: body,
				},
				options
			)
		)
		return this.client.createToken(data)
	}
}
