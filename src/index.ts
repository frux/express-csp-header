import crypto from 'crypto';

import { getCSP, CSPHeaderParams, nonce } from 'csp-header';
import { RequestHandler, Request, Response } from 'express';
import { parseDomain, ParseResultType } from 'parse-domain';

import { NONCE, TLD } from './constants';

export * from './constants';

type ReportUriFunction = (req: Request, res: Response) => string;

export interface ExpressCSPParams extends Omit<CSPHeaderParams, 'reportUri'> {
    reportOnly?: boolean,
    reportUri?: string | ReportUriFunction,
}

export function expressCspHeader(params?: ExpressCSPParams): RequestHandler {
    return function (req, res, next) {
        if (!params) {
            next();
            return;
        }

        let cspString = getCspString(req, res, params);
        cspString = applyNonce(req, cspString);
        cspString = applyAutoTld(req, cspString);

        setHeader(res, cspString, params);

        next();
    };
}

function getCspString(req: Request, res: Response, params: ExpressCSPParams): string {
    let { directives, presets, reportUri } = params;
    let cspHeaderParams: CSPHeaderParams = {
        directives,
        presets,
        reportUri: typeof reportUri === 'function' ? reportUri(req, res) : reportUri
    };

    return getCSP(cspHeaderParams);
}

function applyNonce(req: Request, cspString: string): string {
    if (cspString.includes(NONCE)) {
        req.nonce = crypto.randomBytes(16).toString('base64');

        return cspString.replace(new RegExp(NONCE, 'g'), nonce(req.nonce));
    }

    return cspString;
}

function applyAutoTld(req: Request, cspString: string): string {
    if (cspString.includes(TLD)) {
        let result = parseDomain(req.hostname);
        if (ParseResultType.Listed !== result.type) {
			return cspString;
		}

        if (0 === result.topLevelDomains.length) {
            return cspString;
        }

        const tld = result.topLevelDomains.join('.');

        return cspString.replace(new RegExp(TLD, 'g'), tld);
    }

    return cspString;
}

const CSP_HEADER = 'Content-Security-Policy';
const CSP_REPORT_ONLY_HEADER = 'Content-Security-Policy-Report-Only';

function setHeader(res: Response, cspString: string, params: ExpressCSPParams): void {
    let headerName = params.reportOnly ? CSP_REPORT_ONLY_HEADER : CSP_HEADER;
    res.set(headerName, cspString);
}
