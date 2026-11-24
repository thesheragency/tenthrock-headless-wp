import { NextRequest, NextResponse } from 'next/server';
import { after } from 'next/server';
import { forwardToInsightly } from '@/lib/insightly/forward';

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 10;

function getClientIp(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return request.headers.get('x-real-ip') || 'unknown';
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (record.count >= RATE_LIMIT_MAX) {
    return false;
  }

  record.count++;
  return true;
}

const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

/**
 * Verify a reCAPTCHA v3 token with Google. Enforced only when
 * RECAPTCHA_SECRET_KEY is configured, so forms keep working before the keys are
 * set.
 *
 * Consent-gated reCAPTCHA: the site runs the Usercentrics "Smart Data Protector"
 * cookie-consent manager, which blocks Google's reCAPTCHA script until the
 * visitor accepts the reCAPTCHA cookie category. Visitors who decline (or
 * haven't interacted with the banner) therefore mint NO token — that's a normal
 * legitimate state, not a bot signal. So we fail OPEN on a missing token (the
 * honeypot + rate limiting remain as the floor) and only fail CLOSED when a
 * token IS present but verification fails or the score is too low (a real bot
 * signal). Also fails OPEN on a network error reaching Google so an outage there
 * can't take the contact forms down.
 */
async function verifyRecaptcha(
  token: string | null,
  ip: string
): Promise<{ ok: boolean; score?: number; reason?: string }> {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret) return { ok: true, reason: 'not_configured' };
  // No token = consent not granted (reCAPTCHA blocked by the CMP). Allow through.
  if (!token) return { ok: true, reason: 'missing_token' };

  const params = new URLSearchParams({ secret, response: token });
  if (ip && ip !== 'unknown') params.set('remoteip', ip);

  let json: any;
  try {
    const res = await fetch(RECAPTCHA_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });
    json = await res.json();
  } catch (err) {
    console.error('reCAPTCHA verify request failed (failing open):', err);
    return { ok: true, reason: 'verify_unreachable' };
  }

  const minScore = Number(process.env.RECAPTCHA_MIN_SCORE ?? '0.5');
  if (!json.success) {
    return {
      ok: false,
      score: json.score,
      reason: `failed:${(json['error-codes'] || []).join(',')}`,
    };
  }
  // Bind the token to the action our client mints (submit-client uses
  // "gf_submit"). A mismatch means a token issued for a different purpose on the
  // same public site key is being replayed here — a bot signal, so fail CLOSED.
  if (json.action && json.action !== 'gf_submit') {
    return { ok: false, score: json.score, reason: `action_mismatch:${json.action}` };
  }
  if (typeof json.score === 'number' && json.score < minScore) {
    return { ok: false, score: json.score, reason: 'low_score' };
  }
  return { ok: true, score: json.score };
}

function getWpRestBaseUrl(): string {
  // Prefer the canonical REST URL, then derive from the GraphQL URL or the
  // legacy WP_API_URL secret. All three resolve to the same `<host>/wp-json` base.
  const candidate =
    process.env.WORDPRESS_REST_URL ||
    process.env.WORDPRESS_GRAPHQL_URL ||
    process.env.WP_API_URL;
  if (!candidate) {
    throw new Error(
      'No WordPress URL configured (set WORDPRESS_REST_URL, WORDPRESS_GRAPHQL_URL, or WP_API_URL)'
    );
  }
  const url = new URL(candidate);
  return `${url.protocol}//${url.host}/wp-json`;
}

export async function POST(request: NextRequest) {
  const ip = getClientIp(request);

  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: 'Too many submissions. Please try again later.' },
      { status: 429 }
    );
  }

  try {
    const formData = await request.formData();
    const formId = formData.get('formId');
    const honeypot = formData.get('gf_hp');

    // Honeypot check - silently succeed for bots
    if (honeypot) {
      return NextResponse.json({
        is_valid: true,
        confirmation_message: 'Thank you for your submission.',
        entry_id: null,
      });
    }

    // reCAPTCHA v3 verification (enforced only when RECAPTCHA_SECRET_KEY is set).
    const recaptchaToken = formData.get('recaptcha_token');
    const recaptcha = await verifyRecaptcha(
      typeof recaptchaToken === 'string' ? recaptchaToken : null,
      ip
    );
    if (!recaptcha.ok) {
      console.warn(
        'reCAPTCHA rejected submission:',
        recaptcha.reason,
        'score=',
        recaptcha.score
      );
      return NextResponse.json(
        { error: "We couldn't verify that you're human. Please try again." },
        { status: 400 }
      );
    }

    if (!formId) {
      return NextResponse.json(
        { error: 'formId is required' },
        { status: 400 }
      );
    }

    // Build FormData for WordPress REST API
    const wpFormData = new FormData();
    
    // Copy all input_ prefixed fields to wpFormData (including files)
    // Gravity Forms REST API expects input_{fieldId} or input_{fieldId}.{subInputId} format
    const inputFieldPattern = /^input_\d+(?:[._]\d+)?$/;
    
    for (const [key, value] of formData.entries()) {
      if (inputFieldPattern.test(key)) {
        // Value could be a string or File - FormData handles both
        wpFormData.append(key, value);
      }
    }

    const wpRestUrl = getWpRestBaseUrl();
    const submitUrl = `${wpRestUrl}/gf/v2/forms/${formId}/submissions`;

    const headers: Record<string, string> = {};

    // Gravity Forms REST API v2 requires Basic Auth with consumer key/secret
    // (issued via WP → Forms → Settings → REST API). The site-wide WP_AUTH_USER
    // creds are GraphQL-only and will be rejected here with 401.
    if (process.env.GF_CONSUMER_KEY && process.env.GF_CONSUMER_SECRET) {
      const credentials = Buffer.from(
        `${process.env.GF_CONSUMER_KEY}:${process.env.GF_CONSUMER_SECRET}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    } else {
      console.error('GF_CONSUMER_KEY / GF_CONSUMER_SECRET not configured — submission will likely fail.');
    }

    // Gravity Forms answers a form with a redirect confirmation with a 302
    // (Location = the confirmation URL) and the JSON result in the body.
    // Don't follow it: following re-requests the thank-you page, which fails
    // or returns HTML. The JSON body already holds the result.
    const response = await fetch(submitUrl, {
      method: 'POST',
      headers,
      body: wpFormData,
      redirect: 'manual',
    });

    const isRedirect = response.status >= 300 && response.status < 400;
    const rawBody = await response.text();
    let data: any;
    try {
      data = JSON.parse(rawBody);
    } catch {
      console.error('Gravity Forms REST API returned non-JSON:', response.status, rawBody.slice(0, 200));
      return NextResponse.json({ error: 'Submission failed' }, { status: 502 });
    }

    if (!response.ok && !isRedirect) {
      console.error('Gravity Forms REST API error:', data);
      return NextResponse.json(
        { error: data.message || 'Submission failed', validation_messages: data.validation_messages },
        { status: response.status }
      );
    }

    // REST API returns: { is_valid, confirmation_message, entry_id, validation_messages }
    if (!data.is_valid) {
      return NextResponse.json(
        { 
          is_valid: false,
          validation_messages: data.validation_messages,
          error: 'Validation failed'
        },
        { status: 400 }
      );
    }

    // Surface the confirmation object from upstream EXACTLY as Gravity Forms
    // returns it — the redirect destination is fully editor-managed in
    // WP → Forms → Confirmations. We do NOT rewrite or normalize the URL here;
    // whatever the editor configures (an absolute URL is recommended so there's
    // no cross-domain hop) is what the client follows. GF nests the resolved
    // confirmation under `data.form.confirmation` and also exposes
    // `confirmation_redirect` / `confirmation_type` at the top level.
    let confirmation = data?.form?.confirmation ?? null;
    if (!confirmation && data.confirmation_type === 'redirect' && data.confirmation_redirect) {
      confirmation = { type: 'redirect', url: data.confirmation_redirect };
    }
    // Forward to Insightly CRM as a Lead. Deferred with `after()` so the
    // user-facing response (and thank-you redirect) returns immediately;
    // Next.js keeps the serverless invocation alive until this resolves
    // instead of killing it the moment the response is sent.
    // Wrapped + caught inside `forwardToInsightly` so it can NEVER break
    // the user-facing form.
    const formIdNum = Number(formId);
    const referer = request.headers.get('referer');
    if (Number.isFinite(formIdNum)) {
      after(() => forwardToInsightly(formIdNum, formData, referer));
    }

    return NextResponse.json({
      is_valid: true,
      confirmation_message: data.confirmation_message,
      confirmation,
      entry_id: data.entry_id,
    });
  } catch (error: unknown) {
    console.error('Error submitting to Gravity Forms REST API:', error);
    
    let errorMessage = 'Failed to submit form';
    if (error instanceof Error) {
      errorMessage = error.message;
    }
    
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
