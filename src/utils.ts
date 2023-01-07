import qs from 'querystring'
import type { ClientOAuth2Options } from './ClientOAuth2'
import { ERROR_RESPONSES } from './constants'

/**
 * Check if properties exist on an object and throw when they aren't.
 */
export function expects(obj: any, ...args: any[]) {
	for (let i = 1; i < args.length; i++) {
		const prop = args[i]
		if (obj[prop] == null) {
			throw new TypeError('Expected "' + prop + '" to exist')
		}
	}
}

/**
 * Pull an authentication error from the response data.
 */
export function getAuthError(body: any): string {
	const message =
		ERROR_RESPONSES[body.error] || body.error_description || body.error

	if (message) {
		const err = new Error(message) as any
		err.body = body
		err.code = 'EAUTH'
		return err
	}
}

/**
 * Ensure a value is a string.
 */
function toString(str: string | null | undefined) {
	return str == null ? '' : String(str)
}

/**
 * Sanitize the scopes option to be a string.
 */
export function sanitizeScope(scopes: string[] | string): string {
	return Array.isArray(scopes) ? scopes.join(' ') : toString(scopes)
}

/**
 * Create basic auth header.
 */
export function auth(username: string, password: string): string {
	return (
		'Basic ' +
		Buffer.from(toString(username) + ':' + toString(password)).toString(
			'base64'
		)
	)
}

/**
 * Create a request uri based on an options object and token type.
 */
export function createUri(
	options: ClientOAuth2Options,
	tokenType: string
): string {
	// Check the required parameters are set.
	expects(options, 'clientId', 'authorizationUri')

	const query: any = {
		client_id: options.clientId,
		redirect_uri: options.redirectUri,
		response_type: tokenType,
		state: options.state,
	}
	if (options.scopes !== undefined) {
		query.scope = sanitizeScope(options.scopes)
	}

	const sep = options.authorizationUri.includes('?') ? '&' : '?'
	return (
		options.authorizationUri +
		sep +
		qs.stringify(Object.assign(query, options.query))
	)
}

/**
 * Merge request options from an options object.
 */
export function requestOptions(
	{ url, method, body, query, headers }: any,
	options: any
) {
	const rOptions = {
		url: url,
		method: method,
		body: Object.assign({}, body, options.body),
		query: Object.assign({}, query, options.query),
		headers: Object.assign({}, headers, options.headers),
	}
	// if request authorization was overridden delete it from header
	if (rOptions.headers.Authorization === '') {
		delete rOptions.headers.Authorization
	}
	return rOptions
}
