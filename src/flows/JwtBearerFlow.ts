import type { ClientOAuth2 } from '../ClientOAuth2'
import type { ClientOAuth2Token } from '../ClientOAuth2Token'
import { DEFAULT_HEADERS } from '../constants'
import { auth, expects, requestOptions, sanitizeScope } from '../utils'

/**
 * Support JSON Web Token (JWT) Bearer Token OAuth 2.0 grant.
 *
 * Reference: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-2.1
 */
export class JwtBearerFlow {
	constructor(private client: ClientOAuth2) {}

	/**
	 * Request an access token using a JWT token.
	 */
	async getToken(token: string, opts?: any): Promise<ClientOAuth2Token> {
		const options: any = Object.assign({}, this.client.options, opts)
		const headers: any = Object.assign({}, DEFAULT_HEADERS)

		expects(options, 'accessTokenUri')

		// Authentication of the client is optional, as described in
		// Section 3.2.1 of OAuth 2.0 [RFC6749]
		if (options.clientId) {
			headers.Authorization = auth(options.clientId, options.clientSecret)
		}

		const body: Record<string, string> = {
			grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			assertion: token,
		}

		if (options.scopes !== undefined) {
			body.scope = sanitizeScope(options.scopes)
		}

		const data = await this.client.request(
			requestOptions(
				{
					url: options.accessTokenUri,
					method: 'POST',
					headers: headers,
					body: body,
				},
				options
			)
		)

		return this.client.createToken(data)
	}
}
