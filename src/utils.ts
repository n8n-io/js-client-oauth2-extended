import type { RequestObject } from './ClientOAuth2'
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
 * Merge request options from an options object.
 */
export function requestOptions(
	{ url, method, body, query, headers }: RequestObject,
	options: any
): RequestObject {
	const rOptions = {
		url: url,
		method: method,
		body: { ...body, ...options.body },
		query: { ...query, ...options.query },
		headers: { ...headers, ...options.headers },
	}
	// if request authorization was overridden delete it from header
	if (rOptions.headers.Authorization === '') {
		delete rOptions.headers.Authorization
	}
	return rOptions
}
